// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod getresource;
pub mod keyprovider;

#[cfg(feature = "ttrpc")]
pub mod ttrpc_protocol;
#[cfg(feature = "ttrpc")]
pub type TtrpcService =
    std::collections::HashMap<String, Box<dyn ::ttrpc::MethodHandler + Send + Sync>>;

use crate::AttestationAgent;

pub const AGENT_NAME: &str = "attestation-agent";

#[cfg(feature = "ttrpc")]
const PROTOCOL: &str = "ttrpc";
#[cfg(feature = "grpc")]
const PROTOCOL: &str = "grpc";

lazy_static! {
    pub static ref ABOUT: String = {
        let aa_about = AttestationAgent::new().about();
        format!("Protocol: {PROTOCOL}\n{aa_about}")
    };
}
