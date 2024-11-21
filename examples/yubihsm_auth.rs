use yubihsm::{Client, Connector, HttpConfig};
use yubikey::YubiKey;

fn main() {
    let connector = Connector::http(&HttpConfig::default());

    let yubikey = YubiKey::open().unwrap();

    let pending = Client::open_with_yubikey(connector, 18, "YourAuthKeyLabel", yubikey).unwrap();
    println!("Touch the yubikey");
    let client = pending.realize(b"0000").unwrap();

    let list = client.list_objects(&[]).unwrap();
    println!("{list:#?}");
}
