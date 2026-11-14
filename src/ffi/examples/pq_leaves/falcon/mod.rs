pub struct Falcon512;
impl crate::common::Scheme for Falcon512 { type Item = (); const NAME: &'static str = "falcon512"; fn source() -> String { todo!() } fn items(_: usize) -> Vec<()> { todo!() } fn claim(_: &()) -> [u8; 32] { todo!() } fn push_hints(_: &(), _: &mut crate::common::Hints) {} fn forge(_: &()) {} }
