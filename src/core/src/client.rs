#![allow(unreachable_patterns)] // used to catch possible error types not yet defined by dependencies

use crate::config::VoprfGroup;
use crate::crystal::{
    crystal_error, decode_bytes_from_crystal, decode_string_from_crystal,
    encode_string_for_crystal, error_json_retval, JSONRetVal,
};
use crate::NONCE_BYTES;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use privacypass::amortized_tokens::{AmortizedBatchTokenRequest, AmortizedBatchTokenResponse};
use privacypass::auth::authenticate::parse_www_authenticate_header;
use privacypass::common::private::deserialize_public_key;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::ffi::c_char;
use tls_codec::Serialize as TlsSerializeTrait;
use voprf::Group;

use http::header::HeaderValue;

#[derive(Serialize, Deserialize)]
pub struct JSONTokens {
    pub tokens: Vec<String>,
    pub error: String,
}
#[derive(Serialize, Deserialize)]
struct HexNonce(#[serde(with = "hex")] Vec<u8>);

#[derive(Serialize, Deserialize)]
struct HexBlind(#[serde(with = "hex")] Vec<u8>);

#[derive(Serialize, Deserialize)]
pub struct StateTokenRequestRetval {
    pub token_request: String,
    pub state: String,
    pub error: String,
}

#[derive(Serialize, Deserialize)]
struct MyTokenReqState {
    nonces_s: Vec<HexNonce>,
    blinds_s: Vec<HexBlind>,
}

/// # Safety
///
/// Callers must provide a valid NUL terminated string pointer.
#[no_mangle]
pub unsafe extern "C" fn gen_token_request(
    www_authenticate_header_cstr: *const i8,
    nr: u16,
) -> *const c_char {
    // NOTE: the value of result below would not be *const i8
    //       if the begin_panic_handling and end_panic_handling macros where not there
    begin_panic_handling!();
    let result = panic::catch_unwind(|| {
        let www_authenticate_header_s =
            unsafe { decode_string_from_crystal(www_authenticate_header_cstr) }?;
        let header_value: HeaderValue = HeaderValue::from_str(&www_authenticate_header_s)?;
        let challenges = parse_www_authenticate_header(&header_value)?;
        match challenges.len() {
            1 => Ok(()),
            _ => Err(crystal_error("more than one TokenChallenge in header")),
        }?;
        let challenge = &challenges[0];

        // parse issuer public key
        let public_key = deserialize_public_key::<VoprfGroup>(challenge.token_key())
            .map_err(|_| crystal_error("failed to deserialize public key"))?;
        let token_challenge = challenge.token_challenge();

        // generate token nonces
        let mut nonces = Vec::with_capacity(nr as usize);
        for _ in 0..nr {
            let mut nonce = [0u8; NONCE_BYTES];
            OsRng.fill_bytes(&mut nonce);
            nonces.push(nonce);
        }

        // serialise token nonces
        let nonces_s: Vec<_> = nonces
            .iter()
            .map(|nonce| HexNonce(nonce.to_vec()))
            .collect();

        // generate blinding factors
        let blinds = (0..nr)
            .map(|_| <VoprfGroup as Group>::random_scalar(&mut OsRng))
            .collect::<Vec<_>>();

        // serialise blinding factors
        let blinds_s = blinds
            .iter()
            .map(|blind| HexBlind(<VoprfGroup as Group>::serialize_scalar(*blind).to_vec()))
            .collect::<Vec<_>>();

        // create a token request corresponding to the challenge, nonces and blinding factors
        let (token_request, _) =
            AmortizedBatchTokenRequest::<VoprfGroup>::issue_token_request_with_params(
                public_key,
                token_challenge,
                nonces,
                blinds,
            )
            .map_err(|e| crystal_error(&format!("failed to create token request: {e}")))?;

        // serialise token request
        let token_request_bytes = token_request.tls_serialize_detached()?;
        let token_request_s = URL_SAFE.encode(token_request_bytes);

        let state_vector = MyTokenReqState { nonces_s, blinds_s };
        let state_vector_s = serde_json::to_string_pretty(&state_vector)?;

        let state_token_request_rv = StateTokenRequestRetval {
            token_request: token_request_s,
            state: state_vector_s,
            error: "".to_string(),
        };

        let state_token_request_rv_s = serde_json::to_string(&state_token_request_rv)?;
        let rv = JSONRetVal {
            retval: state_token_request_rv_s,
            error: "".to_string(),
        };

        let rv_s = serde_json::to_string(&rv)?;
        let out = encode_string_for_crystal(rv_s)?;

        // always end like this
        Ok::<*const i8, Box<dyn std::error::Error>>(out)
    });
    end_panic_handling!();
    result
}

#[no_mangle]
pub unsafe extern "C" fn gen_token(
    www_authenticate_header_cstr: *const i8,
    client_state_cstr: *const i8,
    token_response_cstr: *const i8,
) -> *const c_char {
    // NOTE: the value of result below would not be *const i8
    //       if the begin_panic_handling and end_panic_handling macros where not there
    begin_panic_handling!();
    let result = panic::catch_unwind(|| {
        // parse inputs
        let www_authenticate_header_s =
            unsafe { decode_string_from_crystal(www_authenticate_header_cstr) }?;
        let header_value: HeaderValue = HeaderValue::from_str(&www_authenticate_header_s)?;
        let challenges = parse_www_authenticate_header(&header_value)?;
        match challenges.len() {
            1 => Ok(()),
            _ => Err(crystal_error("more than one TokenChallenge in header")),
        }?;
        let challenge = &challenges[0];
        let token_response_bytes = unsafe { decode_bytes_from_crystal(token_response_cstr) }?;
        let client_state_s = unsafe { decode_string_from_crystal(client_state_cstr) }?;

        // parse issuer public key
        let public_key = deserialize_public_key::<VoprfGroup>(challenge.token_key())
            .map_err(|_| crystal_error("failed to deserialize public key"))?;

        // parse token response
        let token_response =
            AmortizedBatchTokenResponse::<VoprfGroup>::try_from_bytes(token_response_bytes.as_slice())
                .map_err(|_| crystal_error("failed to deserialise TokenResponse"))?;

        // count how many tokens the server actually evaluated
        let nr = token_response.evaluated_elements().len();

        // parse nonce and blinding term previously sampled
        let state_vector: MyTokenReqState = match serde_json::from_str(&client_state_s) {
            Ok(req) => Ok(req),
            Err(_) => Err(crystal_error("failed deserializing client's state")),
        }?;

        let nonces: Vec<[u8; NONCE_BYTES]> = match state_vector
            .nonces_s
            .iter()
            .take(nr)
            .map(|nonce| <[u8; NONCE_BYTES]>::try_from(nonce.0.clone()))
            .collect()
        {
            Ok(res) => Ok(res),
            Err(_) => Err(crystal_error(
                "client state vector nonces are longer than expected, can't parse",
            )),
        }?;

        let blinds = match state_vector
            .blinds_s
            .iter()
            .take(nr)
            .map(|blind| VoprfGroup::deserialize_scalar(&blind.0))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(res) => Ok(res),
            Err(_) => Err(crystal_error("failed to deserialize blinding factors")),
        }?;

        // parse token challenge from origin
        let token_challenge = challenge.token_challenge();

        // regenerate token state with the first `nr` nonces/blinds
        let (_, token_state) =
            AmortizedBatchTokenRequest::<VoprfGroup>::issue_token_request_with_params(
                public_key,
                token_challenge,
                nonces,
                blinds,
            )
            .map_err(|e| crystal_error(&format!("failed to recreate token state: {e}")))?;

        // unblind tokens (Finalize)
        let raw_tokens = token_response
            .issue_tokens(&token_state)
            .map_err(|e| crystal_error(&format!("failed to issue tokens: {e}")))?;

        // serialise tokens
        let tokens_buf = raw_tokens
            .into_iter()
            .map(|token| token.tls_serialize_detached())
            .collect::<Result<Vec<Vec<u8>>, _>>()?;

        let tokens_s = tokens_buf
            .into_iter()
            .map(|token_buf| URL_SAFE.encode(token_buf))
            .collect::<Vec<_>>();

        let tokens_rv = JSONTokens {
            tokens: tokens_s,
            error: "".to_string(),
        };

        let tokens_rv_s = serde_json::to_string(&tokens_rv)?;
        let rv = JSONRetVal {
            retval: tokens_rv_s,
            error: "".to_string(),
        };

        let rv_s = serde_json::to_string(&rv)?;
        let out = encode_string_for_crystal(rv_s)?;

        // always end like this
        Ok::<*const i8, Box<dyn std::error::Error>>(out)
    });
    end_panic_handling!();
    result
}
