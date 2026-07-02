//! TPM response buffer sizing for TBS / `/dev/tpmrm0` reads.
//!
//! Do not query `GetCapability` here — that command goes through `submit_tpm_command`, which
//! would deadlock if capacity init called back into transport.

/// Bytes to allocate for one TPM response read.
pub fn tpm_response_buffer_capacity() -> usize {
    8192
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_capacity_at_least_4096() {
        assert!(tpm_response_buffer_capacity() >= 4096);
    }
}
