#[macro_export]
macro_rules! cstring {
  ($x:expr) => {
    CString::new($x).unwrap()
  }
}