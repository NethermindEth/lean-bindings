pub struct MlDsa44;
impl crate::common::Scheme for MlDsa44 { type Item = (); const NAME: &'static str = "mldsa44"; fn source() -> String { todo!() } fn items(_: usize) -> Vec<()> { todo!() } fn claim(_: &()) -> [u8; 32] { todo!() } fn push_hints(_: &(), _: &mut crate::common::Hints) {} fn forge(_: &()) {} }
