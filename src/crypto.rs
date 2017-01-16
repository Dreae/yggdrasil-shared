use ring::aead;
use serde_json;
use ring::rand::SystemRandom;
use serde::ser::Serialize;
use serde::de::Deserialize;
use rustc_serialize::base64::FromBase64;
use rustc_serialize::base64::ToBase64;
use rustc_serialize::base64::STANDARD;

#[derive(Serialize, Deserialize)]
pub struct EncryptedAPIObject {
  pub nonce: String,
  pub data: String
}

lazy_static! {
  pub static ref SECRAND: SystemRandom = SystemRandom::new();
}

pub fn decrypt(key: &[u8], obj: &EncryptedAPIObject) -> String {
  let data = obj.data.from_base64().expect("Data is not valid base64");
  let nonce = obj.nonce.from_base64().expect("Nonce is not valid base64");
  
  let mut data_buffer = Vec::with_capacity(data.len());
  data_buffer.clone_from(&data);

  let ref opening_key = aead::OpeningKey::new(&aead::CHACHA20_POLY1305, &pad_key_as_needed(key)).expect("Unable to create opening_key");
  
  let plaintext_size = aead::open_in_place(opening_key, &nonce, 0, &mut data_buffer, &[]).expect("Unable to decrypt data");

  String::from_utf8(Vec::from(&data_buffer[..plaintext_size])).expect("Data is not valid UTF8")
}

pub fn encrypt(key: &[u8], data: &str) -> EncryptedAPIObject {
  let suffix_space = aead::CHACHA20_POLY1305.max_overhead_len();
  let nonce_len = aead::CHACHA20_POLY1305.nonce_len();

  let mut nonce = vec![0; nonce_len];
  SECRAND.fill(&mut nonce).expect("Error generating nonce");

  let ref sealing_key = aead::SealingKey::new(&aead::CHACHA20_POLY1305, &pad_key_as_needed(key)).expect("Unable to create sealing_key");
  
  let mut buffer = Vec::from(data);
  buffer.reserve(suffix_space);
  for _ in 0..suffix_space {
    buffer.push(0);
  }

  aead::seal_in_place(sealing_key, &nonce, &mut buffer, suffix_space, &[]).expect("Unable to encrypt data");

  EncryptedAPIObject {
    nonce: nonce.to_base64(STANDARD),
    data: buffer.to_base64(STANDARD),
  }
}

pub fn encrypt_obj<T>(key: &[u8], obj: &T) -> EncryptedAPIObject where T: Serialize  {
  let data = serde_json::to_string(obj).expect("Error serializing object");
  encrypt(key, &data)
}

pub fn decrypt_obj<T>(key: &[u8], api_obj: &EncryptedAPIObject) -> T where T: Deserialize {
  let data = decrypt(key, api_obj);
  serde_json::from_str(&data).expect("Error deserializing plaintext")
}

fn pad_key_as_needed(key: &[u8]) -> Vec<u8> {
  let key_len = aead::CHACHA20_POLY1305.key_len();
  if key.len() < key_len {
    let mut vec = Vec::from(key);
    for _ in key.len()..key_len {
      vec.push(0);
    }

    vec
  } else {
    Vec::from(key)
  }
}

#[cfg(test)]
mod tests {
  #[test]
  fn encrypt_decrypt_data() {
    let api_obj = super::encrypt("foobarfoobar1234foobarfoobar1234".to_owned().as_bytes(), "123456789abcdef0");
    let data = super::decrypt("foobarfoobar1234foobarfoobar1234".to_owned().as_bytes(), &api_obj);
    assert_eq!(data, "123456789abcdef0");
  }

  #[derive(Serialize, Deserialize)]
  struct Point {
    x: i32,
    y: i32,
  }

  #[test]
  fn encrypt_decrypt_objects() {
    let point = Point {
      x: 1,
      y: 2,
    };

    let api_obj = super::encrypt_obj("foobar".to_owned().as_bytes(), &point);
    let point_out: Point = super::decrypt_obj("foobar".to_owned().as_bytes(), &api_obj);
    assert_eq!(point_out.x, 1);
    assert_eq!(point_out.y, 2);
  }

  #[test]
  fn pad_keys() {
    let api_obj = super::encrypt("foobar".to_owned().as_bytes(), "123456789abcdef0");
    let data = super::decrypt("foobar".to_owned().as_bytes(), &api_obj);
    assert_eq!(data, "123456789abcdef0");
  }
}