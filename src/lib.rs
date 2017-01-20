#[macro_use] extern crate serde_derive;
#[macro_use] extern crate lazy_static;
extern crate rocket;
extern crate rustc_serialize;
extern crate serde_json;
extern crate serde;
extern crate ring;

pub mod macros;
pub mod crypto;
pub mod models;