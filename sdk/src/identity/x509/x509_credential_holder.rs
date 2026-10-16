// Copyright 2025 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

use c2pa_raw_crypto::RawSigner;

use crate::{
    crypto::{
        cose::{cose_reserve_size, sign, RawSignerCoseSigner, TimeStampStorage},
        time_stamp::TimeStampProvider,
    },
    identity::{
        builder::{CredentialHolder, IdentityBuilderError},
        SignerPayload,
    },
};

/// An implementation of [`CredentialHolder`] that generates COSE signatures
/// using X.509 credentials as specified in [§8.2, X.509 certificates and COSE
/// signatures].
///
/// [`SignatureVerifier`]: crate::identity::SignatureVerifier
/// [§8.2, X.509 certificates and COSE signatures]: https://cawg.io/identity/1.1-draft/#_x_509_certificates_and_cose_signatures
pub struct X509CredentialHolder {
    signer: Box<dyn RawSigner + Sync + Send + 'static>,
    cert_chain: Vec<Vec<u8>>,
    time_stamp_provider: Option<Box<dyn TimeStampProvider + Sync + Send + 'static>>,
}

impl X509CredentialHolder {
    /// Create an `X509CredentialHolder` instance by wrapping an instance of
    /// [`RawSigner`] together with its signing certificate chain (each
    /// certificate in DER form, end-entity first).
    ///
    /// [`RawSigner`]: crate::RawSigner
    pub fn from_raw_signer(
        signer: Box<dyn RawSigner + Sync + Send + 'static>,
        cert_chain: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            signer,
            cert_chain,
            time_stamp_provider: None,
        }
    }

    /// Request an [RFC 3161] time stamp over each identity signature from
    /// `provider` and store it in that signature's `sigTst2` header.
    ///
    /// This method is temporary and will be superseded by an official c2pa-rs
    /// method in time.
    ///
    /// [RFC 3161]: https://datatracker.ietf.org/doc/html/rfc3161
    pub fn with_time_stamp_provider(
        mut self,
        provider: Box<dyn TimeStampProvider + Sync + Send + 'static>,
    ) -> Self {
        self.time_stamp_provider = Some(provider);
        self
    }
}

impl CredentialHolder for X509CredentialHolder {
    fn sig_type(&self) -> &'static str {
        super::CAWG_X509_SIG_TYPE
    }

    fn reserve_size(&self) -> usize {
        cose_reserve_size(
            self.signer.max_signature_size(),
            &self.cert_chain,
            self.time_stamp_provider.is_some(),
            None,
        )
    }

    fn sign(&self, signer_payload: &SignerPayload) -> Result<Vec<u8>, IdentityBuilderError> {
        // TO DO: Check signing cert (see signing_cert_valid in c2pa-rs's cose_sign).

        let mut sp_cbor: Vec<u8> = vec![];
        c2pa_cbor::to_writer(&mut sp_cbor, signer_payload)
            .map_err(|e| IdentityBuilderError::CborGenerationError(e.to_string()))?;

        sign(
            &RawSignerCoseSigner::new(
                self.signer.as_ref(),
                &self.cert_chain,
                self.time_stamp_provider.as_deref().map(|p| p as _),
            ),
            &sp_cbor,
            None,
            TimeStampStorage::V2_sigTst2_CTT,
        )
        .map_err(|e| IdentityBuilderError::SignerError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::io::{Cursor, Seek};

    use c2pa_macros::c2pa_test_async;
    use chrono::{TimeZone, Utc};
    use coset::{CoseSign1, TaggedCborSerializable};
    use rasn::types::{Any, ObjectIdentifier, Oid, SetOf};
    use rasn_cms::{
        tsp::{MessageImprint, PkiStatus, PkiStatusInfo, TimeStampResp, TstInfo, TST_INFO},
        CertificateChoices, ContentInfo, EncapsulatedContentInfo, IssuerAndSerialNumber,
        SignedData, SignerIdentifier, SignerInfo, CONTENT_SIGNED_DATA,
    };
    use rasn_pkix::{AlgorithmIdentifier, Certificate};
    use sha2::{Digest, Sha256};
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::{
        crypto::{
            cose::{validate_cose_tst_info, CertificateTrustPolicy, Verifier},
            time_stamp::{TimeStampError, TimeStampProvider},
        },
        identity::{
            builder::{IdentityAssertionBuilder, IdentityAssertionSigner},
            tests::fixtures::{cert_chain_and_private_key_for_alg, manifest_json, parent_json},
            x509::{X509CredentialHolder, X509SignatureVerifier},
            IdentityAssertion,
        },
        status_tracker::StatusTracker,
        Builder, Reader, SigningAlg,
    };

    const TEST_IMAGE: &[u8] = include_bytes!("../../../tests/fixtures/CA.jpg");
    const TEST_THUMBNAIL: &[u8] = include_bytes!("../../../tests/fixtures/thumbnail.jpg");

    #[c2pa_test_async]
    async fn simple_case() {
        // Create a context with decode_identity_assertions disabled
        let settings = crate::settings::Settings::default()
            .with_value("core.decode_identity_assertions", false)
            .unwrap();
        let context = crate::Context::new()
            .with_settings(settings)
            .unwrap()
            .into_shared();

        let format = "image/jpeg";
        let mut source = Cursor::new(TEST_IMAGE);
        let mut dest = Cursor::new(Vec::new());

        // Use the context when creating the Builder
        let mut builder = Builder::from_shared_context(&context)
            .with_definition(manifest_json())
            .unwrap();
        builder
            .add_ingredient_from_stream(parent_json(), format, &mut source)
            .unwrap();

        builder
            .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
            .unwrap();

        let mut c2pa_signer = IdentityAssertionSigner::from_test_credentials(SigningAlg::Ps256);

        let (cawg_cert_chain, cawg_private_key) =
            cert_chain_and_private_key_for_alg(SigningAlg::Ed25519);

        let cawg_raw_signer =
            c2pa_raw_crypto::signer_from_private_key(&cawg_private_key, SigningAlg::Ed25519)
                .unwrap();

        let cawg_cert_chain_der = crate::crypto::cert_chain_pem_to_der(&cawg_cert_chain).unwrap();

        let x509_holder =
            X509CredentialHolder::from_raw_signer(cawg_raw_signer, cawg_cert_chain_der);
        let iab = IdentityAssertionBuilder::for_credential_holder(x509_holder);
        c2pa_signer.add_identity_assertion(iab);

        builder
            .sign(&c2pa_signer, format, &mut source, &mut dest)
            .unwrap();

        // Read back the Manifest that was generated using the same context
        dest.rewind().unwrap();

        let manifest_store = Reader::from_shared_context(&context)
            .with_stream(format, &mut dest)
            .unwrap();
        assert_eq!(manifest_store.validation_status(), None);

        let manifest = manifest_store.active_manifest().unwrap();
        let mut st = StatusTracker::default();
        let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

        // Should find exactly one identity assertion.
        let ia = ia_iter.next().unwrap().unwrap();
        assert!(ia_iter.next().is_none());
        drop(ia_iter);

        // And that identity assertion should be valid for this manifest.
        let x509_verifier = X509SignatureVerifier {
            cose_verifier: Verifier::IgnoreProfileAndTrustPolicy,
        };

        let sig_info = ia
            .validate(manifest, &mut st, &x509_verifier)
            .await
            .unwrap();

        let cert_info = &sig_info.cert_info;
        assert_eq!(cert_info.alg.unwrap(), SigningAlg::Ed25519);
        assert_eq!(
            cert_info.issuer_org.as_ref().unwrap(),
            "C2PA Test Signing Cert"
        );
        assert_eq!(cert_info.common_name.as_ref().unwrap(), "C2PA Signer");

        // No need to restore settings - we never modified global state!
    }

    // in-test RFC 3161 TSA: the Ed25519 test credential signs a TSTInfo over each request
    struct TestTimeStampProvider;

    impl TimeStampProvider for TestTimeStampProvider {
        fn send_time_stamp_request(
            &self,
            message: &[u8],
        ) -> Option<Result<Vec<u8>, TimeStampError>> {
            let (cert_chain, private_key) = cert_chain_and_private_key_for_alg(SigningAlg::Ed25519);
            let cert_der = &crate::crypto::cert_chain_pem_to_der(&cert_chain).unwrap()[0];
            let cert: Certificate = rasn::der::decode(cert_der).unwrap();

            let sha256_alg = AlgorithmIdentifier {
                algorithm: Oid::JOINT_ISO_ITU_T_COUNTRY_US_ORGANIZATION_GOV_CSOR_NIST_ALGORITHMS_HASH_SHA256
                    .to_owned(),
                parameters: None,
            };

            let tst_info = rasn::der::encode(&TstInfo {
                version: 1.into(),
                // arbitrary policy
                policy: ObjectIdentifier::new(vec![1, 2, 3]).unwrap(),
                message_imprint: MessageImprint {
                    hash_algorithm: sha256_alg.clone(),
                    hashed_message: Sha256::digest(message).to_vec().into(),
                },
                serial_number: 1.into(),
                // inside the Ed25519 test certificate's validity (2022-2030)
                gen_time: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap().into(),
                accuracy: None,
                ordering: false,
                nonce: None,
                tsa: None,
                extensions: None,
            })
            .unwrap();

            let signature =
                c2pa_raw_crypto::signer_from_private_key(&private_key, SigningAlg::Ed25519)
                    .unwrap()
                    .sign(&tst_info)
                    .unwrap();

            let signed_data = SignedData {
                version: 3.into(),
                digest_algorithms: SetOf::from_vec(vec![sha256_alg.clone()]),
                encap_content_info: EncapsulatedContentInfo {
                    content_type: TST_INFO.to_owned(),
                    content: Some(tst_info.into()),
                },
                certificates: Some(SetOf::from_vec(vec![CertificateChoices::Certificate(
                    Box::new(cert.clone()),
                )])),
                crls: None,
                signer_infos: SetOf::from_vec(vec![SignerInfo {
                    version: 1.into(),
                    sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                        issuer: cert.tbs_certificate.issuer,
                        serial_number: cert.tbs_certificate.serial_number,
                    }),
                    digest_algorithm: sha256_alg,
                    signed_attrs: None,
                    signature_algorithm: cert.tbs_certificate.subject_public_key_info.algorithm,
                    signature: signature.into(),
                    unsigned_attrs: None,
                }]),
            };

            let response = TimeStampResp {
                status: PkiStatusInfo {
                    status: PkiStatus::Granted,
                    status_string: None,
                    fail_info: None,
                },
                time_stamp_token: Some(ContentInfo {
                    content_type: CONTENT_SIGNED_DATA.to_owned(),
                    content: Any::new(rasn::der::encode(&signed_data).unwrap()),
                }),
            };

            Some(Ok(rasn::der::encode(&response).unwrap()))
        }
    }

    #[test]
    fn identity_signature_carries_time_stamp() {
        let settings = crate::settings::Settings::default()
            .with_value("core.decode_identity_assertions", false)
            .unwrap();
        let context = crate::Context::new()
            .with_settings(settings)
            .unwrap()
            .into_shared();

        let format = "image/jpeg";
        let mut source = Cursor::new(TEST_IMAGE);
        let mut dest = Cursor::new(Vec::new());

        let mut builder = Builder::from_shared_context(&context)
            .with_definition(manifest_json())
            .unwrap();
        builder
            .add_ingredient_from_stream(parent_json(), format, &mut source)
            .unwrap();

        builder
            .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
            .unwrap();

        let mut c2pa_signer = IdentityAssertionSigner::from_test_credentials(SigningAlg::Ps256);

        let (cawg_cert_chain, cawg_private_key) =
            cert_chain_and_private_key_for_alg(SigningAlg::Ed25519);

        let cawg_raw_signer =
            c2pa_raw_crypto::signer_from_private_key(&cawg_private_key, SigningAlg::Ed25519)
                .unwrap();

        let x509_holder = X509CredentialHolder::from_raw_signer(
            cawg_raw_signer,
            crate::crypto::cert_chain_pem_to_der(&cawg_cert_chain).unwrap(),
        )
        .with_time_stamp_provider(Box::new(TestTimeStampProvider));
        let iab = IdentityAssertionBuilder::for_credential_holder(x509_holder);
        c2pa_signer.add_identity_assertion(iab);

        builder
            .sign(&c2pa_signer, format, &mut source, &mut dest)
            .unwrap();

        dest.rewind().unwrap();

        let reader = Reader::from_shared_context(&context)
            .with_stream(format, &mut dest)
            .unwrap();
        let manifest = reader.active_manifest().unwrap();

        let mut st = StatusTracker::default();
        let ia = IdentityAssertion::from_manifest(manifest, &mut st)
            .next()
            .unwrap()
            .unwrap();
        let sign1 = CoseSign1::from_tagged_slice(&ia.signature).unwrap();

        // sigTst2 time stamps the identity signature itself, so it needs no payload
        validate_cose_tst_info(
            &sign1,
            &[],
            &CertificateTrustPolicy::passthrough(),
            &mut st,
            false,
        )
        .unwrap();
    }
}
