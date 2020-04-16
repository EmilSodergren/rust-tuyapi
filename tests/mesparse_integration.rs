use rust_tuyapi::mesparse::{CommandType, Message, MessageParser};

#[test]
fn encode_and_decode_message() {
    let payload = r#"{"devId":"002004265ccf7fb1b659","dps":{"1":false,"2":0}}"#
        .as_bytes()
        .to_owned();

    let parser = MessageParser::create("3.1", None).unwrap();
    let message_to_encode = Message::new(&payload, Some(CommandType::DpQuery), 2);
    let encoded = parser.encode(&message_to_encode, false).unwrap();

    let decoded = parser.parse(&encoded).unwrap();

    assert_eq!(message_to_encode, decoded[0]);
}
