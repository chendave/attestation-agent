// Copyright (c) 2023 Arm Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::*;
use std::path::Path;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::close;
use serde::{Deserialize, Serialize};
use base64::Engine;

// NOTE: The path might be different when the CCA feature is public available, will come back to update the actual path is needed.
pub fn detect_platform() -> bool {
    Path::new("/dev/cca_attestation").exists()
}

#[derive(Debug, Default)]
pub struct CCAAttester {}

#[derive(Serialize, Deserialize)]
struct CcaEvidence {
    // Cca token
    token: Vec<u8>,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct cca_ioctl_request {
    challenge: [u8; 64],
    token: [u8; 4096],
    token_length: u64,
}

nix::ioctl_readwrite!(cca_attestation_request, b'A', 1, cca_ioctl_request);


#[async_trait::async_trait]
impl Attester for CCAAttester {
    async fn get_evidence(&self, _: Vec<u8>) -> Result<String> {
        let challenge = [0u8; 64];
        let token = attestation(&challenge, 0).unwrap();
        let evidence = CcaEvidence {token};
        serde_json::to_string(&evidence)
        .map_err(|e| anyhow!("Serialize CCA evidence failed: {:?}", e))
    }
}


fn attestation(challenge: &[u8], _challenge_id: i32) -> Result<Vec<u8>, Error>{
    log::info!("cca_test::attestation started");

    match open("/dev/cca_attestation", OFlag::empty(), Mode::empty()) {
        Result::Ok(f) => {
            log::info!("cca_test::attestation opening attestation succeeded");
            let mut r = cca_ioctl_request {
                challenge: [0u8; 64],
                token: [0u8; 4096],
                token_length: 0u64
            };

            let mut i : usize = 0;
            let j : usize = std::cmp::min(r.challenge.len(), challenge.len());
            while i < j {
                r.challenge[i] = challenge[i];
                i += 1;
            }

            match unsafe { cca_attestation_request(f, &mut r) } {
                Result::Ok(c) => {
                    log::info!("cca_test::attestation ioctl call succeeded ({})", c);
                    log::info!("cca_test::attestation token is {} bytes long", r.token_length);
                    let base64 = base64::engine::general_purpose::STANDARD.encode(&r.token[0..(r.token_length as usize)]);
                    log::info!("cca_test::attestation token = {:x?}", base64);
                    let token = r.token[0..(r.token_length as usize)].to_vec();
                    close(f).unwrap();
                    Ok(token)
                }
                Err(e) => {
                    log::error!("cca_test::attestation ioctl failed! {}", e);
                    close(f).unwrap();
                    Err(anyhow!(e))
                }
            }
        }
        Err(err) => {
            log::error!("cca_test::attestation opening attestation failed! {}", err);
            Err(anyhow!(err))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[tokio::test]
    async fn test_cca_get_evidence() {
        let attester = CCAAttester::default();
        let report_data: Vec<u8> = vec![0; 48];
        let evidence = attester.get_evidence(report_data).await;
        assert!(evidence.is_ok());
    }
}