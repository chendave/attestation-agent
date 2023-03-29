// Copyright (c) 2023 Arm Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::*;
use std::env;


// If the environment variable "CCA_ATTESTER" is set,
// the TEE platform is considered as "CCA".
pub fn detect_platform() -> bool {
    env::var("CCA_ATTESTER").is_ok()
}


#[derive(Debug, Default)]
pub struct CCAAttester {}

// NOTE: If we sign the evidence here rather by a veraison proxy (proxy to veraison verifier), we need to rustify the cbor lib to support the logic around signature.
#[allow(unused_variables)]
impl Attester for CCAAttester {
    fn get_evidence(&self, data: String) -> Result<String> {
        let s = std::include_str!("cca-claims-without-realm-challenge.json").as_bytes();
        let evidence = String::from_utf8_lossy(s);
        println!("evidence: {}", evidence);
        serde_json::to_string(&evidence).map_err(|_| anyhow!("Serialize evidence failed"))
    }
}
