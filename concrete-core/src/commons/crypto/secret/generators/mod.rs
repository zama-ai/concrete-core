mod encryption;
#[cfg(feature = "parallel")]
pub use encryption::ParallelEncryptionRandomGeneratorInterface;
pub use encryption::{
    DynamicEncryptionRandomGenerator, EncryptionRandomGenerator,
    SequentialEncryptionRandomGeneratorInterface,
};

mod secret;
pub use secret::{
    DynamicSecretRandomGenerator, SecretRandomGenerator, SecretRandomGeneratorInterface,
};
