use crate::core::oblivious_prf::{
    EncryptedInput,
    EncryptedPrfOutput,
    ObliviousPrf,
};

pub struct Transcryptor {
    oblivious_prf: ObliviousPrf,
}

impl Transcryptor {
    pub fn new(oblivious_prf: ObliviousPrf) -> Self {
        Self { oblivious_prf }
    }

    pub fn evaluate_prf(
        &self,
        input: &EncryptedInput,
    ) -> EncryptedPrfOutput {
        self.oblivious_prf.evaluate(input)
    }
}