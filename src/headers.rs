use crate::eth_utils::{sign_clob_auth_message, EthSigner};
use crate::utils::{build_hmac_signature, get_current_unix_time_secs};
use crate::ApiCreds;
use alloy_primitives::hex::encode_prefixed;
use alloy_primitives::U256;
use anyhow::Result;
use serde::Serialize;
use std::collections::HashMap;

const POLY_ADDR_HEADER: &str = "POLY_ADDRESS";
const POLY_SIG_HEADER: &str = "POLY_SIGNATURE";
const POLY_TS_HEADER: &str = "POLY_TIMESTAMP";
const POLY_NONCE_HEADER: &str = "POLY_NONCE";
const POLY_API_KEY_HEADER: &str = "POLY_API_KEY";
const POLY_PASS_HEADER: &str = "POLY_PASSPHRASE";

//TODO: Heapless for maps!
type Headers = HashMap<&'static str, String>;

pub fn create_l1_headers(signer: &impl EthSigner, nonce: Option<U256>) -> Result<Headers> {
    let timestamp = get_current_unix_time_secs().to_string();
    let nonce = nonce.unwrap_or(U256::ZERO);
    let signature = sign_clob_auth_message(signer, timestamp.clone(), nonce)?;
    let address = encode_prefixed(signer.address().as_slice());

    Ok(HashMap::from([
        (POLY_ADDR_HEADER, address),
        (POLY_SIG_HEADER, signature),
        (POLY_TS_HEADER, timestamp),
        (POLY_NONCE_HEADER, nonce.to_string()),
    ]))
}

pub fn create_l2_headers<T>(
    signer: &impl EthSigner,
    api_creds: &ApiCreds,
    method: &str,
    req_path: &str,
    body: Option<&T>,
) -> Result<Headers>
where
    T: ?Sized + Serialize,
{
    let address = encode_prefixed(signer.address().as_slice());
    let timestamp = get_current_unix_time_secs();

    let hmac_signature =
        build_hmac_signature(&api_creds.secret, timestamp, method, req_path, body)?;

    Ok(HashMap::from([
        (POLY_ADDR_HEADER, address),
        (POLY_SIG_HEADER, hmac_signature),
        (POLY_TS_HEADER, timestamp.to_string()),
        (POLY_API_KEY_HEADER, api_creds.api_key.clone()),
        (POLY_PASS_HEADER, api_creds.passphrase.clone()),
    ]))
}
