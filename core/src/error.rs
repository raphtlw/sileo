use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

#[derive(Debug, Clone)]
pub struct SileoError(String);

impl Error for SileoError {}

impl Display for SileoError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl SileoError {
    pub fn new(message: &'static str) -> Box<dyn Error> {
        Box::new(Self(message.into()))
    }
}
