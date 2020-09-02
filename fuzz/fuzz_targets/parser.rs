

//! Nom parser for FMTP
use nom::IResult;
use nom::{be_u8, be_u16};
use nom::take_while1;
use nom;
use crate::fmtp::fmtp::*;




#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum MessageCode {
    FmtpMsgAccept, 
    FmtpMsgReject,
    FmtpMsgValidId, 
    FmtpMsgBadId, 
    FmtpMsgData, 
    FmtpMsgHeartBeat,
    FmtpMsgShutdown, 
    FmtpMsgStartup,
    FmtpMsgUndefined(u8)
}
// impl MessageCode {
//     fn from_u8(value: u8) -> MessageCode {
//         match value {
//             1 => MessageCode::FmtpMsgAccept,
//             2 => MessageCode::FmtpMsgReject, 
//             3 => MessageCode::FmtpMsgValidId, 
//             4 => MessageCode::FmtpMsgBadId, 
//             5 => MessageCode::FmtpMsgData, 
//             6 => MessageCode::FmtpMsgHeartBeat, 
//             7 => MessageCode::FmtpMsgShutdown, 
//             8 => MessageCode::FmtpMsgStartup,

//             _ => MessageCode::FmtpMsgUndefined(value),
//         }
//     }
// }
//Parse du FMTP header
//donc suivant les valeurs Hex dans le paquet 
//elles sont retransmises en big endian, il faut donc les 
//traiter octect par octet en faisant des shift droit (d'où >>)
named!(pub fmtp_parse_header<FMTPHeader>,
    do_parse!(
        version: be_u8 >>
        reserved: be_u8 >> 
        length: be_u16 >> 
        mtype: be_u8 >> 

        (
            FMTPHeader{
                version: version,
                reserved: reserved,
                length: length,
                mtype: mtype,
            }
        )
    )
);

//Parse du Message FMTP d'après le type
//Vérifier chaque caractère par rapport à l'offset jusqu'à la EOL
pub fn ascii_parse_data<'a>(_input: &'a [u8], slice: &'a [u8]) -> IResult<&'a [u8], &'a [u8]> {
    take_while1!(slice, |data| data >= 0x20 && data < 0x7F)
}

pub fn fmtp_parse_data<'a>(slice: &'a [u8]) -> IResult<&'a [u8], FMTPData> {
    let taille_slice = slice.len();
    println!("taille slice : {}", taille_slice);
    let data_struct : IResult<&'a[u8], FMTPData> = 
        do_parse!(
            slice,
            data: call!(ascii_parse_data, slice) >> (

                FMTPData {
                    message: data.iter().cloned().collect(),
                }
            )
        );
    match data_struct {
        nom::IResult::Done(_, result) => {
            match result.message.len() == taille_slice{
                true => {
                    println!("{}", taille_slice);
                    println!("real lenght {}", result.message.len());
                    return nom::IResult::Done(slice, result);
                }
                false => {
                    println!("taille différente");
                    return nom::IResult::Incomplete(nom::Needed::Size(taille_slice)); //faut modifier la valeur de retour ici
                }
            }
            
        }
        nom::IResult::Incomplete(d) => {
            println!("Incompleted");
            return nom::IResult::Incomplete(d);
        }
        nom::IResult::Error(err) => {
            println!("errored");
            return nom::IResult::Error(err);
        }
    }
}


// fmtp_parse_message 
pub fn fmtp_parse_message<'a>( message: &'a [u8]) -> IResult<&'a[u8], FMTPMessage>{

    let _input = message;
    // Vérification du header
    do_parse!(
        message,
        header: fmtp_parse_header >>
        data: fmtp_parse_data >>
        (
            FMTPMessage{
                header: header,
                data: data,
            }
        )
    )
}

#[cfg(test)]
mod tests {

    use super::*;

    // Test fmtp_parse_data 
    #[test]
    fn test_fmtp_parse_data() {
        let buf: &[u8] = &[
            0x30, 0x31                    /* 0030 ...........01    */
        ];
        let vect_buf = buf.to_vec();
        let (_remainder, data_packet) = fmtp_parse_data(buf).unwrap();
        assert_eq!(data_packet.message, vect_buf);
        let s = match std::str::from_utf8(&data_packet.message) {
            Ok(v) => v,
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };
        println!("{}", s);

    }

    // Test fmtp_parse_message 
    #[test]
    fn test_fmtp_parse_message_header() {
        let buf: &[u8] = &[
            0x08, 0x08, 0x08, 0x44, 0x44, 0x44, 0x00, 0x22, 0x83, 0x56, 0x65, 0xfd, 0x08, 0x00, 0x45, 0x00, /* 0000 ...DDD.".Ve...E. */
            0x00, 0x3c, 0x1f, 0x91, 0x40, 0x00, 0x3e, 0x06, 0x42, 0xfd, 0x64, 0x02, 0x01, 0x95, 0x6f, 0x24, /* 0010 .<..@.>.B.d...o$ */
            0x05, 0x73, 0x21, 0x34, 0xca, 0x3b, 0xe0, 0x6c, 0x6e, 0x44, 0x6c, 0x63, 0x0a, 0xd0, 0x50, 0x18, /* 0020 .s!4.;.lnDlc..P. */
            0x00, 0xe5, 0xee, 0x0e, 0x00, 0x00, 0x02, 0x00, 0x00, 0x14, 0x03, 0x52, 0x45, 0x49, 0x4d, 0x53, /* 0030 ...........REIMS */
            0x5f, 0x46, 0x52, 0x2d, 0x47, 0x45, 0x4e, 0x45, 0x56, 0x41                                      /* 0040 _FR-GENEVA       */
                    ];
        
        // The FMTP payload starts at offset 54 (0x36)
        let fmtp_payload = &buf[54..];

        let (_remainder, message_parsed) = fmtp_parse_message(fmtp_payload).unwrap();
        assert_eq!(message_parsed.header.version, 2);
        assert_eq!(message_parsed.header.reserved, 0);

        println!("{}", &message_parsed.header.mtype);
    }

    #[test]
    fn test_fmtp_parse_message_data() {
        let buf: &[u8] = &[
            0x08, 0x08, 0x08, 0x44, 0x44, 0x44, 0x00, 0x22, 0x83, 0x56, 0x65, 0xfd, 0x08, 0x00, 0x45, 0x00, /* 0000 ...DDD.".Ve...E. */
            0x00, 0x3c, 0x1f, 0x91, 0x40, 0x00, 0x3e, 0x06, 0x42, 0xfd, 0x64, 0x02, 0x01, 0x95, 0x6f, 0x24, /* 0010 .<..@.>.B.d...o$ */
            0x05, 0x73, 0x21, 0x34, 0xca, 0x3b, 0xe0, 0x6c, 0x6e, 0x44, 0x6c, 0x63, 0x0a, 0xd0, 0x50, 0x18, /* 0020 .s!4.;.lnDlc..P. */
            0x00, 0xe5, 0xee, 0x0e, 0x00, 0x00, 0x02, 0x00, 0x00, 0x14, 0x03, 0x52, 0x45, 0x49, 0x4d, 0x53, /* 0030 ...........REIMS */
            0x5f, 0x46, 0x52, 0x2d, 0x47, 0x45, 0x4e, 0x45, 0x56, 0x41                                      /* 0040 _FR-GENEVA       */
                    ];
        
        let fmtp_payload = &buf[54..];

        let (_remainder, message_parsed) = fmtp_parse_message(fmtp_payload).unwrap();
        let s = match std::str::from_utf8(&message_parsed.data.message) {
            Ok(v) => v,
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };
        //assert_eq!(s, "REIMS_FR-GENEVA");
        println!("{}", s.len());
        println!("{}", message_parsed.data.message.len());
        println!("{}", s);
    }
}