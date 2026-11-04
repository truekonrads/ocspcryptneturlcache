use anyhow::{bail, Result};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine,
};
use der::Decode;
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use x509_ocsp::{BasicOcspResponse, CertId, OcspRequest, OcspResponse};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CertificateId {
    pub serial: String,
    pub hash_algorithm_oid: String,
    pub issuer_name_hash: String,
    pub issuer_key_hash: String,
}

impl From<CertId> for CertificateId {
    fn from(id: CertId) -> Self {
        let serial = hex::encode_upper(id.serial_number.as_bytes());
        let serial = serial.trim_start_matches('0');
        Self {
            serial: if serial.is_empty() { "0" } else { serial }.to_owned(),
            hash_algorithm_oid: id.hash_algorithm.oid.to_string(),
            issuer_name_hash: hex::encode_upper(id.issuer_name_hash.as_bytes()),
            issuer_key_hash: hex::encode_upper(id.issuer_key_hash.as_bytes()),
        }
    }
}

/// Try each path suffix: standard base64 may contain literal '/', including
/// when a responder lives under a path prefix. Never assume the last segment.
pub fn from_url(url: &str) -> Result<Vec<CertificateId>> {
    let Some((_, after_scheme)) = url.split_once("://") else {
        return Ok(vec![]);
    };
    let Some(slash) = after_scheme.find('/') else {
        return Ok(vec![]);
    };
    let path = after_scheme[slash..]
        .split(['?', '#'])
        .next()
        .unwrap_or_default();
    // Charge all suffix bytes before decoding, bounding both allocation and CPU
    // even when many overlapping suffixes contain plausible base64/DER prefixes.
    let mut remaining = 4 * 1024 * 1024;
    for (offset, _) in path.match_indices('/') {
        let candidate = &path[offset + 1..];
        if candidate.len() > remaining {
            bail!("OCSP URL decoding work limit exceeded; URL evidence retained");
        }
        remaining -= candidate.len();
        let decoded = percent_decode_str(candidate).collect::<Vec<_>>();
        let bytes = STANDARD
            .decode(&decoded)
            .or_else(|_| STANDARD_NO_PAD.decode(&decoded));
        if let Ok(bytes) = bytes {
            if let Ok(request) = OcspRequest::from_der(&bytes) {
                return Ok(request
                    .tbs_request
                    .request_list
                    .into_iter()
                    .map(|r| r.req_cert.into())
                    .collect());
            }
        }
    }
    Ok(vec![])
}

/// POST OCSP requests do not encode a CertID in their URL; cached response
/// bodies still contain it. These are parsed as evidence, not trusted/verified.
pub fn from_response(bytes: &[u8]) -> Vec<CertificateId> {
    let Ok(response) = OcspResponse::from_der(bytes) else {
        return vec![];
    };
    let Some(body) = response.response_bytes else {
        return vec![];
    };
    if body.response_type.to_string() != "1.3.6.1.5.5.7.48.1.1" {
        return vec![];
    }
    let Ok(basic) = BasicOcspResponse::from_der(body.response.as_bytes()) else {
        return vec![];
    };
    basic
        .tbs_response_data
        .responses
        .into_iter()
        .map(|r| r.cert_id.into())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    const REQUEST: &str = "MFMwUTBPME0wSzAJBgUrDgMCGgUABBRI2smg%2ByvTLU%2Fw3mjS9We3NfmzxAQUFC6zF7dYVsuuUAlA5h%2BvnYsUwsYCEgNJysJh3kjaVPgcXCDHUNNWsA%3D%3D";

    #[test]
    fn decodes_notebook_request_and_unescaped_slashes() {
        for path in [
            REQUEST.to_string(),
            percent_decode_str(REQUEST)
                .decode_utf8()
                .unwrap()
                .to_string(),
        ] {
            let ids = from_url(&format!("http://example.test/ocsp/{path}?ignored=1")).unwrap();
            assert_eq!(ids.len(), 1);
            assert_eq!(ids[0].serial, "349CAC261DE48DA54F81C5C20C750D356B0");
            assert_eq!(
                ids[0].issuer_name_hash,
                "48DAC9A0FB2BD32D4FF0DE68D2F567B735F9B3C4"
            );
            assert_eq!(
                ids[0].issuer_key_hash,
                "142EB317B75856CBAE500940E61FAF9D8B14C2C6"
            );
            assert_eq!(ids[0].hash_algorithm_oid, "1.3.14.3.2.26");
        }
    }

    #[test]
    fn extracts_all_ids_from_post_response_and_rejects_truncation() {
        use der::{
            asn1::{BitString, OctetString},
            DateTime, Encode,
        };
        use x509_ocsp::{CertStatus, ResponderId, ResponseData, SingleResponse};

        let bytes = STANDARD
            .decode(percent_decode_str(REQUEST).collect::<Vec<_>>())
            .unwrap();
        let request = OcspRequest::from_der(&bytes).unwrap();
        let id = request.tbs_request.request_list[0].req_cert.clone();
        let mut other_id = id.clone();
        other_id.issuer_key_hash = OctetString::new(vec![0x42; 20]).unwrap();
        let timestamp = DateTime::new(2024, 3, 5, 6, 7, 8).unwrap().into();
        let basic = BasicOcspResponse {
            tbs_response_data: ResponseData {
                version: Default::default(),
                responder_id: ResponderId::ByKey(OctetString::new(vec![0x11; 20]).unwrap()),
                produced_at: timestamp,
                responses: [id.clone(), other_id]
                    .into_iter()
                    .map(|cert_id| SingleResponse {
                        cert_id,
                        cert_status: CertStatus::good(),
                        this_update: timestamp,
                        next_update: None,
                        single_extensions: None,
                    })
                    .collect(),
                response_extensions: None,
            },
            signature_algorithm: id.hash_algorithm,
            // Deliberately unsigned: this tool extracts evidence, not trust.
            signature: BitString::from_bytes(&[0]).unwrap(),
            certs: None,
        };
        let bytes = OcspResponse::successful(basic).unwrap().to_der().unwrap();
        let ids = from_response(&bytes);
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0].serial, "349CAC261DE48DA54F81C5C20C750D356B0");
        assert_eq!(
            ids[0].issuer_key_hash,
            "142EB317B75856CBAE500940E61FAF9D8B14C2C6"
        );
        assert_eq!(
            ids[1].issuer_key_hash,
            "4242424242424242424242424242424242424242"
        );
        for len in 0..bytes.len() {
            assert!(from_response(&bytes[..len]).is_empty());
        }
    }

    #[test]
    fn unrelated_or_malformed_entries_are_not_ocsp() {
        for url in [
            "http://example.test/a.crl",
            "http://example.test/AAAA",
            "not a URL",
            "https://example.test/",
        ] {
            assert!(from_url(url).unwrap().is_empty());
        }
        assert!(from_response(b"not DER").is_empty());
    }
}
