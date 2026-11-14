pub struct SlhDsa128s;
impl crate::common::Scheme for SlhDsa128s { type Item = (); const NAME: &'static str = "slhdsa128s"; fn source() -> String { todo!() } fn items(_: usize) -> Vec<()> { todo!() } fn claim(_: &()) -> [u8; 32] { todo!() } fn push_hints(_: &(), _: &mut crate::common::Hints) {} fn forge(_: &()) {} }
