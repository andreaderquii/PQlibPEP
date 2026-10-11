use crate::core::rlwe_pke::Ciphertext;

pub struct EncryptedInput {
    pub bits: Vec<Ciphertext>,
}

pub struct EncryptedPrfOutput {
    pub ciphertext: Ciphertext,
}

pub struct ObliviousPrf;

impl ObliviousPrf {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate(
        &self,
        _input: &EncryptedInput,
    ) -> EncryptedPrfOutput {
        todo!("BPR12 blind evaluation not implemented yet")
    }
}