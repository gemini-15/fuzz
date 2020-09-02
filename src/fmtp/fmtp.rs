extern crate nom;

use std;
use std::ffi::CString;
use std::mem::transmute;
use crate::core::{self, AppProto, ALPROTO_UNKNOWN};
use crate::core::STREAM_TOSERVER;
use applayer::LoggerFlags;
use parser::*;
use super::parser;
use crate::log::*;
use libc;

// En représentation des différents types de messages, les évènements
// associés à ces derniers 

pub const MAX_LENGTH : u16 = 10240;
//Types de messages
pub const FMTP_TYPE_OPERATIONAL_MESSAGE: u8 = 1;
pub const FMTP_TYPE_OPERATOR_MESSAGE: u8 = 2;
pub const FMTP_TYPE_IDENTIFICATION_MESSAGE: u8 = 3;
pub const FMTP_TYPE_SYSTEM_MESSAGE: u8 = 4;




// Défini le Application Layer Protocol, utilisé par la suite dans les
// fonctions de register et autres
static mut ALPROTO_FMTP_RUST: AppProto = ALPROTO_UNKNOWN;


// défini ici les évents, je pense retournés par suricata 
// pour expliquer pourquoi le paquet n'a pas bien été traité
// Cela peut-être donc une erreur de codage, ou que les headers 
// du paquets sont mal configuré et ne s'agit donc pas du protocole FMTP
pub enum FMTPEvent {
    MalformedData = 0,
    FalselyEncoded = 1, 
    HeaderErrorVersion = 2,
    HeaderErrorReserved = 3,
    HeaderErrorMtype = 4,
    ConnectionStateError = 5, // Rajout d'un nouvel event servant donc à faire un traçage des états 
                    // et renvoyer un fmtpEvent s'il la succession des états ne convient pas

}

// impl FMTPEvent {
//     fn from_i32(value: i32) -> Option<FMTPEvent>{
//         match value {
//             0 => Some(FMTPEvent::MalformedData),
//             1 => Some(FMTPEvent::FalselyEncoded),
//             2 => Some(FMTPEvent::HeaderErrorVersion),
//             3 => Some(FMTPEvent::HeaderErrorReserved),
//             4 => Some(FMTPEvent::HeaderErrorMtype),
//             5 => Some(FMTPEvent::ConnectionStateError),
//             _ => None,
//         }
//     }
// }

// enumération définissant les états de la connection
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, PartialOrd)]
pub enum FMTPConnectionState {
    SystemIdPending = 0,
    IdPending = 1, 
    AssociationPending = 2, 
    DataReady = 3,
    EndConnection = 4,
    ErrorConnection= 5,
    
}

// Structure du header
#[derive(Debug,PartialEq)]
#[repr(C)]
pub struct FMTPHeader {
    pub version: u8, //Sur la version FMTP que l'on souhaite implémenter, cette valeur doit être à 2
    pub reserved: u8, // Vérifier si c'est bien égal à 0
    pub length: u16, // Doit être un double octect d'après la spécification
    pub mtype: u8, //Correspondant au FMTP types décrits plus haut

}


// Lors de l'envoi de la requête
#[derive(Debug)]
pub struct FMTPData { //Pareil que ce soit une requête ou un réponse normalement 
    pub message: Vec<u8>, //Les messages étant en ASCII, il suffit donc de prendre un octect
}

#[derive(Debug)]
pub struct FMTPMessage {
    pub header: FMTPHeader, 
    pub data: FMTPData,
}



//Objet FMTP transaction
//contient request et response
#[derive(Debug)]
pub struct FMTPTransaction {
    pub tx_id: u64,
    pub srv: Option<FMTPMessage>,
    pub cli: Option<FMTPMessage>,
    pub logged: LoggerFlags,
    pub de_state: Option<*mut core::DetectEngineState>,
    pub events: *mut core::AppLayerDecoderEvents,
    pub state_msg: parser::MessageCode, //Code de message : retourné par le parse_message
}

impl FMTPTransaction {
    pub fn new() -> FMTPTransaction {
        FMTPTransaction {
            tx_id: 0,
            srv: None, 
            cli: None,
            logged: LoggerFlags::new(),
            de_state: None,
            events: std::ptr::null_mut(),
            state_msg : parser::MessageCode::FmtpMsgUndefined(0)
        }
    }

    pub fn free(&mut self){
        if self.events != std::ptr::null_mut() {
            core::sc_app_layer_decoder_events_free_events(&mut self.events);
        }
        if let Some(state) = self.de_state{
            core::sc_detect_engine_state_free(state);
        }
    }
}

impl Drop for FMTPTransaction {
    fn drop(&mut self){
        self.free();
    }
}

pub struct FMTPState { 
    pub transaction: FMTPTransaction, 
    pub connection_state_srv: FMTPConnectionState,
    pub connection_state_cli: FMTPConnectionState,
    

}
impl FMTPState {
    pub fn new() -> Self {
        Self {
            transaction: FMTPTransaction::new(),
            connection_state_srv: FMTPConnectionState::SystemIdPending,
            connection_state_cli: FMTPConnectionState::IdPending,
        }
    }

    // pub fn free_tx(&mut self, tx_id: u64){
    //     let len = self.transactions.len();
    //     let mut found = false;
    //     let mut index = 0;
    //     for i in 0..len {
    //         let tx = &self.transactions[i];
    //         if tx.tx_id == tx_id + 1 {
    //             found = true;
    //             index = i;
    //             break;
    //         }
    //     }
    //     if found {
    //         self.transactions.remove(index);
    //     }
    // }

    // pub fn get_tx(&mut self, tx_id: u64) -> Option<&FMTPTransaction>{
    //     for tx in &mut self.transactions {
    //         if tx.tx_id == tx_id +1 {
    //             SCLogDebug!("Found FMTP TX with ID : {}", tx_id);
    //             return Some(tx);
    //         }
    //     }

    //     SCLogDebug!("Failed to find FMTP TX with ID : {}", tx_id);
    //     return None;
    // }

    // pub fn new_tx(&mut self) -> FMTPTransaction {
    //     let mut tx = FMTPTransaction::new();
    //     self.tx_id += 1;
    //     tx.tx_id = self.tx_id;
    //     return tx;
    // }

    

    /// Set an event. The event is set on the most recent transaction.
    pub fn set_event(&mut self, event: FMTPEvent) {
        let ev = event as u8;
        core::sc_app_layer_decoder_events_set_event_raw(&mut self.transaction.events, ev);
    }

    // Returns 0 for success / -1 if fail 
    // Self correspond au state du message
    //l'input correspond au flux des paquets envoyés
    // resp correspond à la direction du flux
    pub fn parse_message(&mut self, input: &[u8], resp: bool)
        -> bool {
        //types de messages identification
        let vec_accept : std::vec::Vec<u8> = vec![0x41, 0x43, 0x43, 0x45, 0x50, 0x54];
        let vec_reject : std::vec::Vec<u8>= vec![0x52, 0x45, 0x5A, 0x45, 0x43, 0x54];
        //types de messages system
        let  vec_shutdown : std::vec::Vec<u8> = vec![0x30, 0x30];
        let vec_startup : std::vec::Vec<u8> = vec![0x30, 0x31];
        let vec_heartbeat : std::vec::Vec<u8> = vec![0x30, 0x33];
        //let mut tx = FMTPTransaction::new();
        
        match parser::fmtp_parse_message(input){
            nom::IResult::Done(_, result) => {
                if result.header.version != 2 {
                    SCLogDebug!("FMTP header version error : None equal to 2");
                    self.set_event(FMTPEvent::HeaderErrorVersion);
                    return false;
                }

                if result.header.reserved != 0 {
                    SCLogDebug!("FMTP false header reserved section : None equal to 0");
                    self.set_event(FMTPEvent::HeaderErrorReserved);
                    return false;
                }

                if result.header.mtype > 4 {
                    SCLogDebug!("FMTP false header message type.");
                    self.set_event(FMTPEvent::HeaderErrorMtype);
                    return false;
                }
                if result.header.length >= MAX_LENGTH {
                    SCLogDebug!("Packet length exceeds autorized FMTP packets length");
                    self.set_event(FMTPEvent::MalformedData);
                    return false;
                }
                match result.header.mtype {
                    // Operationnal/Operator Message 
                    FMTP_TYPE_OPERATIONAL_MESSAGE | FMTP_TYPE_OPERATOR_MESSAGE => {
                        self.transaction.state_msg = parser::MessageCode::FmtpMsgData;
                        if self.connection_state_srv != FMTPConnectionState::DataReady || self.connection_state_cli != FMTPConnectionState::DataReady  {
                            self.connection_state_srv = FMTPConnectionState::ErrorConnection;
                            self.connection_state_cli = FMTPConnectionState::ErrorConnection;
                            self.set_event(FMTPEvent::ConnectionStateError);
                        }  
                    }

                    //Identification Message 
                    FMTP_TYPE_IDENTIFICATION_MESSAGE => {
                        if result.data.message == vec_accept {
                            SCLogDebug!("Valid Packet, identification message Accept");
                            self.transaction.state_msg = parser::MessageCode::FmtpMsgAccept;
                            if !resp {
                                if self.connection_state_srv == FMTPConnectionState::IdPending {
                                    self.connection_state_srv = FMTPConnectionState::AssociationPending;
                                } else {
                                    self.connection_state_srv = FMTPConnectionState::ErrorConnection;
                                    self.connection_state_cli = FMTPConnectionState::ErrorConnection;
                                    self.set_event(FMTPEvent::ConnectionStateError);
                                }
                            } else {
                                self.connection_state_srv = FMTPConnectionState::ErrorConnection;
                                self.connection_state_cli = FMTPConnectionState::ErrorConnection;
                                self.set_event(FMTPEvent::ConnectionStateError);
                            }
                        } else if result.data.message == vec_reject {
                            SCLogDebug!("Valid Packet, identification message Reject");
                            self.transaction.state_msg = parser::MessageCode::FmtpMsgReject;
                            if !resp {
                                if self.connection_state_srv == FMTPConnectionState::IdPending {
                                    self.connection_state_srv = FMTPConnectionState::EndConnection;
                                } else {
                                    self.connection_state_srv = FMTPConnectionState::ErrorConnection;
                                    self.connection_state_cli = FMTPConnectionState::ErrorConnection;
                                    self.set_event(FMTPEvent::ConnectionStateError);
                                }
                            } else {
                                self.connection_state_srv = FMTPConnectionState::ErrorConnection;
                                self.connection_state_cli = FMTPConnectionState::ErrorConnection;
                                self.set_event(FMTPEvent::ConnectionStateError);
                            }
                        } else {
                            let taille_data = result.data.message.len();
                            if taille_data < 32 {
                                match result.data.message.iter().find(|&&caract| caract==0x2D) {
                                    Some(&0x2D) => {
                                        // Message d'identification réussi - Id (Valid)
                                        SCLogDebug!("Valid Packet, identification message with hyphen");
                                        self.transaction.state_msg = parser::MessageCode::FmtpMsgValidId;
                                        // si serveur
                                        if !resp {
                                            if self.connection_state_srv != FMTPConnectionState::SystemIdPending {
                                                self.connection_state_srv = FMTPConnectionState::ErrorConnection;
                                                self.set_event(FMTPEvent::ConnectionStateError);
                                            } else {
                                                self.connection_state_srv = FMTPConnectionState::IdPending;
                                            }
                                        // si client
                                        }else {
                                            if self.connection_state_cli == FMTPConnectionState::IdPending {
                                                self.connection_state_cli = FMTPConnectionState::AssociationPending;
                                            } else {
                                                self.connection_state_cli = FMTPConnectionState::ErrorConnection;
                                                self.set_event(FMTPEvent::ConnectionStateError);
                                            }
                                        }
                                        return true;
                                    }
                                    Some(_x) => {
                                        // Id Bad
                                        self.set_event(FMTPEvent::ConnectionStateError);
                                        return false;
                                    }
                                    None => {
                                        // Id Bad
                                        self.set_event(FMTPEvent::ConnectionStateError);
                                        return false;
                                    }
                                }
                            } else{
                                self.set_event(FMTPEvent::FalselyEncoded);
                                return false;
                            }
                        }
                    }

                    //system message
                    FMTP_TYPE_SYSTEM_MESSAGE => {
                        if result.data.message == vec_shutdown {
                            SCLogDebug!("SHUTDOWN system message");
                            self.transaction.state_msg = parser::MessageCode::FmtpMsgShutdown;
                            if !resp {
                                if self.connection_state_srv == FMTPConnectionState::DataReady{
                                    self.connection_state_srv = FMTPConnectionState::AssociationPending;
                                } else {
                                    self.connection_state_srv = FMTPConnectionState::ErrorConnection;
                                    self.set_event(FMTPEvent::ConnectionStateError);
                                }   
                            }else {
                                if self.connection_state_cli == FMTPConnectionState::DataReady{
                                    self.connection_state_cli = FMTPConnectionState::AssociationPending;
                                } else {
                                    self.connection_state_cli = FMTPConnectionState::ErrorConnection;
                                    self.set_event(FMTPEvent::ConnectionStateError);
                                }   
                            }
                            

                        }else if result.data.message == vec_startup {
                            SCLogDebug!("STARTUP system message");
                            self.transaction.state_msg = parser::MessageCode::FmtpMsgStartup;
                            if !resp {
                                if self.connection_state_srv == FMTPConnectionState::AssociationPending{
                                    self.connection_state_srv = FMTPConnectionState::DataReady;
                                } else {
                                    self.connection_state_srv = FMTPConnectionState::ErrorConnection;
                                    self.set_event(FMTPEvent::ConnectionStateError);
                                }
                            }else {
                                if self.connection_state_cli == FMTPConnectionState::AssociationPending{
                                    self.connection_state_cli = FMTPConnectionState::DataReady;
                                } else {
                                    self.connection_state_cli =  FMTPConnectionState::ErrorConnection;
                                    self.set_event(FMTPEvent::ConnectionStateError);
                                }
                            }
                        } else if result.data.message == vec_heartbeat {
                            SCLogDebug!("HEARTBEAT system message");
                            self.transaction.state_msg = parser::MessageCode::FmtpMsgHeartBeat;
                            if !resp {
                                if self.connection_state_srv != FMTPConnectionState::DataReady{
                                    self.connection_state_srv =  FMTPConnectionState::ErrorConnection;
                                    self.set_event(FMTPEvent::ConnectionStateError);
                                }
                                
                            }else {
                                if self.connection_state_cli != FMTPConnectionState::DataReady{
                                    self.connection_state_cli =  FMTPConnectionState::ErrorConnection;
                                    self.set_event(FMTPEvent::ConnectionStateError);
                                }    
                            }

                        } else {
                            self.set_event(FMTPEvent::MalformedData);
                            return false;
                        }
                    }
                    _ => {
                        return false;
                    }
                }
                if !resp {
                    self.transaction.srv = Some(result);
                }
                else {
                    self.transaction.cli = Some(result);
                }
                return true;
            }
            nom::IResult::Incomplete(_) => {
                SCLogDebug!("insufficient data while parsing FMTP message");
                self.set_event(FMTPEvent::MalformedData);
                return false;
            }
            nom::IResult::Error(e) => {
                SCLogDebug!("An Error occured while parsing FMTP message : {}", e);
                self.set_event(FMTPEvent::FalselyEncoded);
                return false;
            }
        }

    }

    // pub fn parse_message(&mut self, input: &[u8]) -> bool {
    //     match parser::fmtp_parse_message(input){
    //         nom::IResult::Done(_, message) => {
    //             if message.header.version != 2 {
    //                 SCLogDebug!("FMTP header version error : None equal to 2");
    //                 self.set_event(FMTPEvent::HeaderErrorVersion);
    //                 return false;
    //             }

    //             if message.header.reserved != 0{
    //                 SCLogDebug!("FMTP false header reserved section : None equal to 0");
    //                 self.set_event(FMTPEvent::HeaderErrorReserved);
    //                 return false;
    //             }

    //             if message.header.mtype < 0 || message.header.mtype > 4 {
    //                 SCLogDebug!("FMTP false header message type.");
    //                 self.set_event(FMTPEvent::HeaderErrorMtype);
    //                 return false;
    //             }
    //             let mut tx = self.new_tx();
    //             tx.request = Some(message);
    //             self.transactions.push(tx);
    //             return true;
    //         }
    //         nom::IResult::Incomplete(_) => {
    //             SCLogDebug!("insufficient data while parsing FMTP message");
    //             self.set_event(FMTPEvent::MalformedData);
    //             return false;
    //         }
    //         nom::IResult::Error(_) => {
    //             SCLogDebug!("An Error occured while parsing FMTP message");
    //             self.set_event(FMTPEvent::MalformedData);
    //             return false;
    //         }
    //     }
    // }

    // pub fn parse_message_tcp(&mut self, input: &[u8]) -> i8 {

    // }

}

#[no_mangle]
pub extern "C" fn rs_fmtp_state_new() -> *mut libc::c_void {
    SCLogNotice!("rs_fmtp_state_new called");
    let state = FMTPState::new();
    let boxed = Box::new(state);
    return unsafe{transmute(boxed)};
}

#[no_mangle]
pub extern "C" fn rs_fmtp_state_free(state: *mut libc::c_void) {
    SCLogNotice!("rs_fmtp_state_free called");
    let _drop: Box<FMTPState> =unsafe{transmute(state)};
} 

#[no_mangle]
pub extern "C" fn rs_fmtp_state_tx_free(_state: *mut libc::c_void, _tx_id: u64) {
    SCLogNotice!("rs_fmtp_state_tx_free called");
}


#[no_mangle]
pub extern "C" fn rs_fmtp_parse_message_request(_flow : *const core::Flow,
                                        state: *mut libc::c_void,
                                        _pstate: *mut libc::c_void,
                                        input: *const u8,
                                        input_len: u32,
                                        _data: *const libc::c_void,
                                        _flags: u8) 
                                         //  Nom 5 -> AppLayerResult {
                                        -> i32 {
    SCLogNotice!("rs_fmtp_parse_message_request called");
    let state = cast_pointer!(state, FMTPState);
    let buf = unsafe{std::slice::from_raw_parts(input, input_len as usize)};
    if state.parse_message(buf, false){
        if state.connection_state_srv != FMTPConnectionState::ErrorConnection{
            return 1;
        }
        else{
            return -1
        }
        //Nom 5 
        // AppLayerResult::ok()
    }
    return -1;
    // } else {

    //     AppLayerResult::err()
    // }
} 

#[no_mangle]
pub extern "C" fn rs_fmtp_parse_message_response(_flow : *const core::Flow,
                                        state: *mut libc::c_void,
                                        _pstate: *mut libc::c_void,
                                        input: *const u8,
                                        input_len: u32,
                                        _data: *const libc::c_void,
                                        _flags: u8) 
                                         //  Nom 5 -> AppLayerResult {
                                        -> i32 {
   SCLogNotice!("rs_fmtp_parse_message_response called");
    let state = cast_pointer!(state, FMTPState);
    let buf = unsafe{std::slice::from_raw_parts(input, input_len as usize)};
    if state.parse_message(buf, true){
        if state.connection_state_cli != FMTPConnectionState::ErrorConnection {
            return 1;
        }
        else{
            return -1
        }
        //Nom 5 
        // AppLayerResult::ok()
    }
    return -1;
    // } else {

    //     AppLayerResult::err()
    // }
} 

#[no_mangle]
pub extern "C" fn rs_fmtp_state_get_tx_count(_state: *mut libc::c_void) -> u64 {
    return 1;
}

#[no_mangle] 
pub extern "C" fn rs_fmtp_state_get_tx(
    state: *mut libc::c_void, _tx_id: u64,
) -> *mut libc::c_void {
    SCLogNotice!("rs_fmtp_get_tx called");

    let state = cast_pointer!(state, FMTPState);
    return unsafe { transmute(&state.transaction) };
}

#[no_mangle] 
pub extern "C" fn rs_fmtp_state_set_tx_detect_state(
    tx: *mut libc::c_void, 
    de_state: &mut core::DetectEngineState) -> libc::c_int 
{
    SCLogNotice!("rs_fmtp_state_set_tx_detect_state called");
    let tx = cast_pointer!(tx, FMTPTransaction);
    tx.de_state = Some(de_state);
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_fmtp_state_get_tx_detect_state(
    tx: *mut libc::c_void) -> *mut core::DetectEngineState 
{
    SCLogNotice!("rs_fmtp_state_get_tx_detect_state called");
    let tx = cast_pointer!(tx, FMTPTransaction);
    match tx.de_state {
        Some(ds) => {
            return ds;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_fmtp_tx_set_logged(_state: *mut libc::c_void,
                                       tx: *mut libc::c_void,
                                       logged: u32)
{
    SCLogNotice!("rs_fmtp_tx_set_logged called");
    let tx = cast_pointer!(tx, FMTPTransaction);
    tx.logged.set(logged);
}

#[no_mangle]
pub extern "C" fn rs_fmtp_tx_get_logged(_state: *mut libc::c_void,
                                       tx: *mut libc::c_void)
                                       -> u32
{
    SCLogNotice!("rs_fmtp_get_logged called");
    let tx = cast_pointer!(tx, FMTPTransaction);
    return tx.logged.get();
}

#[no_mangle]
pub extern "C" fn rs_fmtp_state_get_events(state: *mut libc::c_void, _tx_id: u64)
     -> *mut core::AppLayerDecoderEvents {
    SCLogNotice!("rs_fmtp_state_get_events called");
    let state = cast_pointer!(state, FMTPState);
    let tx = &state.transaction;
    return tx.events;
}

// pub extern "C" fn rs_fmtp_state_get_events(state: *mut libc::c_void, tx_id: u64)
//                                           -> *mut core::AppLayerDecoderEvents
// {
//     let state = cast_pointer!(state, FMTPState);
//     match state.get_tx(tx_id) {
//         Some(tx) => tx.events,
//         _        => std::ptr::null_mut(),
//     }
// }
// Renvoi juste le connectionState pour savoir quand la connection est effectivement terminée 
#[no_mangle]
pub extern "C" fn rs_fmtp_state_progress_completion_status(
    _direction: u8) -> libc::c_int {
        SCLogDebug!("rs_fmtp_state_progress_completion_status");
        SCLogNotice!("rs_fmtp_state_progress_completion_status called");
        return FMTPConnectionState::EndConnection as i32;
}


// TODO: Code copié normalement mais fmtp est stateful car dépend des packets précédemment envoyés 
#[no_mangle]
pub extern "C" fn rs_fmtp_tx_get_alstate_progress(tx: *mut libc::c_void,
                                                 direction: u8)
                                                 -> libc::c_int
{
    // This is a stateless parser, just the existence of a transaction
    // means its complete.
    SCLogDebug!("rs_fmtp_tx_get_alstate_progress");
    SCLogNotice!("rs_fmtp_tx_get_alstate_progress called");
    let tx = cast_pointer!(tx, FMTPTransaction);

    if direction == STREAM_TOSERVER {
        if tx.state_msg ==parser::MessageCode::FmtpMsgReject {
            return FMTPConnectionState::EndConnection as i32;
        }
    }
    else {
        if tx.state_msg == parser::MessageCode::FmtpMsgReject {
            return FMTPConnectionState::EndConnection as i32;
        }
    }
    return FMTPConnectionState::DataReady as i32;
}
pub fn probe(input: &[u8]) -> bool {

    if input.len() > 1 {
        return true;
    }
    return false;
}
#[no_mangle]
pub extern "C" fn rs_fmtp_probe(
    _flow: *const core::Flow,
    input: *const u8,
    len: u32
) -> AppProto {
    SCLogNotice!("rs_fmtp_probe called");
    if len == 0 || len < std::mem::size_of::<FMTPHeader>() as u32 {
        return core::ALPROTO_UNKNOWN;
    }
    let slice: &[u8] = unsafe{
        std::slice::from_raw_parts(input as *mut u8, len as usize)
    };

    let is_fmtp = probe(slice);
    if is_fmtp == true {
        return unsafe{ ALPROTO_FMTP_RUST };
    }
    return core::ALPROTO_UNKNOWN;
}


#[no_mangle]
pub extern "C" fn rs_fmtp_state_get_event_info(
    event_name: *const libc::c_char,
    event_id: *mut libc::c_int,
    event_type: *mut core::AppLayerEventType
) -> libc::c_int {
    SCLogNotice!("rs_fmtp_state_get_event_info called");
    if event_name == std::ptr::null() {
        return -1;
    }

    let c_event_name = unsafe { std::ffi::CStr::from_ptr(event_name) };
    let event = match c_event_name.to_str() {
        Ok(s) => {
            match s {
                "malformed_data" => FMTPEvent::MalformedData as i32,
                "encoding_error" => FMTPEvent::FalselyEncoded as i32,
                "header_version_error" => FMTPEvent::HeaderErrorVersion as i32,
                "header_reserved_error" => FMTPEvent::HeaderErrorReserved as i32,
                "header_mtype_error" => FMTPEvent::HeaderErrorMtype as i32,
                "connection_state_error" => FMTPEvent::ConnectionStateError as i32, 
                _ => -1, // unknown event
            }
        },
        Err(_) => -1, // UTF-8 conversion failed
    };
    unsafe{
        *event_type = core::APP_LAYER_EVENT_TYPE_TRANSACTION;
        *event_id = event as libc::c_int;
    };
    0
}
#[no_mangle]
pub extern "C" fn rs_fmtp_get_request_buffer(
    _tx: *mut libc::c_void,
    _buf: *mut *const u8,
    _len: *mut u32,
) -> u8
{
    SCLogNotice!("rs_fmtp_get_request_buffer called");

    // let tx = cast_pointer!(tx, TemplateTransaction);
    // if let Some(ref request) = tx.srv {
    //     if request.len() > 0 {
    //         unsafe {
    //             *len = request.len() as u32;
    //             *buf = request.as_ptr();
    //         }
    //         return 1;
    //     }
    // }
    return 1;
}

/// Get the response buffer for a transaction from C.
#[no_mangle]
pub extern "C" fn rs_fmtp_get_response_buffer(
    _tx: *mut libc::c_void,
    _buf: *mut *const u8,
    _len: *mut u32,
) -> u8
{
    SCLogNotice!("rs_fmtp_get_response_buffer called");
    // let tx = cast_pointer!(tx, TemplateTransaction);
    // if let Some(ref response) = tx.cli {
    //     if response.len() > 0 {
    //         unsafe {
    //             *len = response.len() as u32;
    //             *buf = response.as_ptr();
    //         }
    //         return 1;
    //     }
    // }
    return 1;
}


//FMTP TCP register parser 
#[no_mangle]
pub unsafe extern "C" fn rs_fmtp_register_parser(){
    let default_port = std::ffi::CString::new("8500").unwrap();
    let parser = RustParser{
        name: b"fmtp-rust\0".as_ptr() as *const libc::c_char,
        default_port: default_port.as_ptr(),
        ipproto: libc::IPPROTO_TCP,
        probe_ts: rs_fmtp_probe, // Pas besoin de probe ici je pense
        probe_tc: rs_fmtp_probe,
        min_depth: 0,
        max_depth: std::mem::size_of::<FMTPHeader>() as u16,
        state_new: rs_fmtp_state_new,
        state_free: rs_fmtp_state_free,
        tx_free: rs_fmtp_state_tx_free,
        parse_ts: rs_fmtp_parse_message_request,
        parse_tc: rs_fmtp_parse_message_response,
        get_tx_count: rs_fmtp_state_get_tx_count,
        get_tx: rs_fmtp_state_get_tx,
        tx_get_comp_st: rs_fmtp_state_progress_completion_status,
        tx_get_progress: rs_fmtp_tx_get_alstate_progress,
        get_tx_logged: Some(rs_fmtp_tx_get_logged),
        set_tx_logged: Some(rs_fmtp_tx_set_logged),
        get_events: Some(rs_fmtp_state_get_events),
        get_eventinfo: Some(rs_fmtp_state_get_event_info),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_mpm_id: None,
        set_tx_mpm_id: None,
        get_files: None,
        get_tx_iterator: None,
        get_tx_detect_flags: None,
        set_tx_detect_flags: None,
        get_de_state: rs_fmtp_state_get_tx_detect_state,
        set_de_state: rs_fmtp_state_set_tx_detect_state,
    };

    let ip_proto_str = CString::new("tcp").unwrap();
    SCLogDebug!("parsing test sclogdebug");
    SCLogNotice!("parsing test SCLogNotice");

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_FMTP_RUST = alproto;
        SCLogNotice!("parserRust successfully called");
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    } else {
        SCLogDebug!("Protocol detector and parser disabled for FMTP.");
    }
}


#[cfg(test)]
mod tests {

    use super::*;
    
    #[test]
    fn test_fmtp_parse_message_valid() {
        let buf: &[u8] = &[
            0x08, 0x08, 0x08, 0x44, 0x44, 0x44, 0x00, 0x22, 0x83, 0x56, 0x65, 0xfd, 0x08, 0x00, 0x45, 0x00, /* 0000 ...DDD.".Ve...E. */
            0x00, 0x3c, 0x1f, 0x91, 0x40, 0x00, 0x3e, 0x06, 0x42, 0xfd, 0x64, 0x02, 0x01, 0x95, 0x6f, 0x24, /* 0010 .<..@.>.B.d...o$ */
            0x05, 0x73, 0x21, 0x34, 0xca, 0x3b, 0xe0, 0x6c, 0x6e, 0x44, 0x6c, 0x63, 0x0a, 0xd0, 0x50, 0x18, /* 0020 .s!4.;.lnDlc..P. */
            0x00, 0xe5, 0xee, 0x0e, 0x00, 0x00, 0x02, 0x00, 0x00, 0x14, 0x03, 0x52, 0x45, 0x49, 0x4d, 0x53, /* 0030 ...........REIMS */
            0x5f, 0x46, 0x52, 0x2d, 0x47, 0x45, 0x4e, 0x45, 0x56, 0x41                                      /* 0040 _FR-GENEVA       */
                    ];
        // The FMTP payload starts at offset 54 (0x36)
        let fmtp_payload = &buf[54..];

        let mut state = FMTPState::new();
        assert_eq!(true, state.parse_message(fmtp_payload, false));


    }

    #[test]
    fn test_fmtp_parse_message_accept() {

        let buf: &[u8] = &[
            0x08, 0x08, 0x08, 0x44, 0x44, 0x44, 0x00, 0x22, 0x83, 0x56, 0x65, 0xfd, 0x08, 0x00, 0x45, 0x00, /* 0000 ...DDD.".Ve...E. */
            0x00, 0x33, 0x6c, 0xa3, 0x40, 0x00, 0x78, 0x06, 0xbb, 0xf3, 0x6f, 0x24, 0x05, 0x73, 0x64, 0x02, /* 0010 .3l.@.x...o$.sd. */
            0x01, 0x95, 0xca, 0x3b, 0x21, 0x34, 0x6c, 0x63, 0x0a, 0xd0, 0xe0, 0x6c, 0x6e, 0x58, 0x50, 0x18, /* 0020 ...;!4lc...lnXP. */
            0x01, 0x02, 0x41, 0x49, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0b, 0x03, 0x41, 0x43, 0x43, 0x45, 0x50, /* 0030 ..AI.......ACCEP */
        0x54                                                                                            /* 0040 T                */
        ];

        // The FMTP payload starts at offset 54 (0x36)
        let fmtp_payload = &buf[54..];

        let mut state = FMTPState::new();
        assert_eq!(true, state.parse_message(fmtp_payload, false));


    }
    #[test]
    fn test_fmtp_parse_message_startup() {

        let buf: &[u8] = &[
            0x08, 0x08, 0x08, 0x44, 0x44, 0x44, 0x00, 0x22, 0x83, 0x56, 0x65, 0xfd, 0x08, 0x00, 0x45, 0x00, /* 0000 ...DDD.".Ve...E. */
            0x00, 0x2f, 0x1f, 0x92, 0x40, 0x00, 0x3e, 0x06, 0x43, 0x09, 0x64, 0x02, 0x01, 0x95, 0x6f, 0x24, /* 0010 ./..@.>.C.d...o$ */
            0x05, 0x73, 0x21, 0x34, 0xca, 0x3b, 0xe0, 0x6c, 0x6e, 0x58, 0x6c, 0x63, 0x0a, 0xdb, 0x50, 0x18, /* 0020 .s!4.;.lnXlc..P. */
            0x00, 0xe5, 0xec, 0x07, 0x00, 0x00, 0x02, 0x00, 0x00, 0x07, 0x04, 0x30, 0x31                    /* 0030 ...........01    */
        ];

        // The FMTP payload starts at offset 54 (0x36)
        let fmtp_payload = &buf[54..];

        let mut state = FMTPState::new();
        assert_eq!(true, state.parse_message(fmtp_payload, false));


    }

    #[test]
    fn test_fmtp_parse_message_heartbeat() {

        let buf: &[u8] = &[
            0x08, 0x08, 0x08, 0x44, 0x44, 0x44, 0x00, 0x22, 0x83, 0x56, 0x65, 0xfd, 0x08, 0x00, 0x45, 0x00, /* 0000 ...DDD.".Ve...E. */
            0x00, 0x2f, 0x6d, 0x4d, 0x40, 0x00, 0x78, 0x06, 0xbb, 0x4d, 0x6f, 0x24, 0x05, 0x73, 0x64, 0x02, /* 0010 ./mM@.x..Mo$.sd. */
            0x01, 0x95, 0xca, 0x3b, 0x21, 0x34, 0x6c, 0x63, 0x0a, 0xe9, 0xe0, 0x6c, 0x6e, 0x66, 0x50, 0x18, /* 0020 ...;!4lc...lnfP. */
            0x01, 0x02, 0xe9, 0xce, 0x00, 0x00, 0x02, 0x00, 0x00, 0x07, 0x04, 0x30, 0x33                    /* 0030 ...........03    */
                    ];
            
        // The FMTP payload starts at offset 54 (0x36)
        let fmtp_payload = &buf[54..];

        let mut state = FMTPState::new();
        assert_eq!(true, state.parse_message(fmtp_payload, false));

    }

    // #[test] 
    // fn test_fmtp_connection_state(){
    //     let buf1: &[u8] = &[
    //         0x08, 0x08, 0x08, 0x44, 0x44, 0x44, 0x00, 0x22, 0x83, 0x56, 0x65, 0xfd, 0x08, 0x00, 0x45, 0x00, /* 0000 ...DDD.".Ve...E. */
    //         0x00, 0x2f, 0x6d, 0x4d, 0x40, 0x00, 0x78, 0x06, 0xbb, 0x4d, 0x6f, 0x24, 0x05, 0x73, 0x64, 0x02, /* 0010 ./mM@.x..Mo$.sd. */
    //         0x01, 0x95, 0xca, 0x3b, 0x21, 0x34, 0x6c, 0x63, 0x0a, 0xe9, 0xe0, 0x6c, 0x6e, 0x66, 0x50, 0x18, /* 0020 ...;!4lc...lnfP. */
    //         0x01, 0x02, 0xe9, 0xce, 0x00, 0x00, 0x02, 0x00, 0x00, 0x07, 0x04, 0x30, 0x33                    /* 0030 ...........03    */
    //                 ];

    //     let fmtp_payload_1 = &buf1[54..];

    //     let buf: &[u8] = &[
    //         0x08, 0x08, 0x08, 0x44, 0x44, 0x44, 0x00, 0x22, 0x83, 0x56, 0x65, 0xfd, 0x08, 0x00, 0x45, 0x00, /* 0000 ...DDD.".Ve...E. */
    //         0x00, 0x3c, 0x1f, 0x91, 0x40, 0x00, 0x3e, 0x06, 0x42, 0xfd, 0x64, 0x02, 0x01, 0x95, 0x6f, 0x24, /* 0010 .<..@.>.B.d...o$ */
    //         0x05, 0x73, 0x21, 0x34, 0xca, 0x3b, 0xe0, 0x6c, 0x6e, 0x44, 0x6c, 0x63, 0x0a, 0xd0, 0x50, 0x18, /* 0020 .s!4.;.lnDlc..P. */
    //         0x00, 0xe5, 0xee, 0x0e, 0x00, 0x00, 0x02, 0x00, 0x00, 0x14, 0x03, 0x52, 0x45, 0x49, 0x4d, 0x53, /* 0030 ...........REIMS */
    //         0x5f, 0x46, 0x52, 0x2d, 0x47, 0x45, 0x4e, 0x45, 0x56, 0x41                                      /* 0040 _FR-GENEVA       */
    //                 ];
    //     let mut state = FMTPState::new();
    //     let success_buf1 = state.parse_message(fmtp_payload_1, true);
    //     assert_eq!(FMTPConnectionState::DataReady, state.connection_state_srv);
    //     let success_buf2 = state.parse_message(fmtp_payload_2, true);
    //     println!("connection state : {}", state.connection_state_srv);
    // }
}