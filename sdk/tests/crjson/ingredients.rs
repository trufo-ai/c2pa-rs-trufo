// Copyright 2024 Adobe. All rights reserved.
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

//! Tests for ingredient assertions in crJSON format

use std::io::Cursor;

use c2pa::{Builder, BuilderIntent, Context, DigitalSourceType, Reader, Result};
use serde_json::Value;

use super::super::common::{test_context, test_settings, test_signer};

const IMAGE_WITH_INGREDIENT: &[u8] = include_bytes!("../fixtures/CA.jpg");
// CA.jpg as the parent ingredient: the ingredient assertion records CA.jpg's
// results at ingest, signingCredential.untrusted among them
const IMAGE_WITH_INGREDIENT_MANIFEST: &[u8] = include_bytes!("../fixtures/CACA.jpg");
// a v2 ingredient assertion recording claimSignature.mismatch for its manifest
const IMAGE_WITH_BAD_INGREDIENT_SIGNATURE: &[u8] = include_bytes!("../fixtures/CIE-sig-CA.jpg");
const IMAGE_WITHOUT_MANIFEST: &[u8] = include_bytes!("../fixtures/no_manifest.jpg");

#[test]
fn test_ingredient_assertions_included() -> Result<()> {
    let reader = Reader::default().with_stream("image/jpeg", Cursor::new(IMAGE_WITH_INGREDIENT))?;
    let json_value = reader.to_crjson_value()?;

    // Get manifests array
    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    // Check first manifest for ingredient assertion
    let first_manifest = manifests
        .first()
        .expect("should have at least one manifest");
    let assertions = first_manifest["assertions"]
        .as_object()
        .expect("assertions should be object");

    // Should have ingredient assertion
    assert!(
        assertions.contains_key("c2pa.ingredient"),
        "assertions should contain c2pa.ingredient"
    );

    // Verify ingredient structure
    let ingredient = &assertions["c2pa.ingredient"];
    assert!(ingredient.is_object(), "ingredient should be an object");

    // Check for expected ingredient fields (spec uses dc: Dublin Core prefixes)
    let ingredient_obj = ingredient.as_object().unwrap();
    assert!(
        ingredient_obj.contains_key("dc:title"),
        "ingredient should have dc:title (Dublin Core, per crJSON spec)"
    );
    assert!(
        ingredient_obj.contains_key("dc:format"),
        "ingredient should have dc:format (Dublin Core, per crJSON spec)"
    );

    // Verify all hashes in ingredient are base64 strings, not byte arrays
    if let Some(c2pa_manifest) = ingredient_obj.get("c2pa_manifest") {
        if let Some(hash) = c2pa_manifest.get("hash") {
            assert!(
                hash.is_string(),
                "ingredient c2pa_manifest hash should be string"
            );
        }
    }

    if let Some(thumbnail) = ingredient_obj.get("thumbnail") {
        if let Some(hash) = thumbnail.get("hash") {
            assert!(
                hash.is_string(),
                "ingredient thumbnail hash should be string"
            );
        }
    }

    Ok(())
}

#[test]
fn test_ingredient_count_matches() -> Result<()> {
    let reader = Reader::default().with_stream("image/jpeg", Cursor::new(IMAGE_WITH_INGREDIENT))?;
    let json_value = reader.to_crjson_value()?;

    // Get manifests array
    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    let first_manifest = manifests
        .first()
        .expect("should have at least one manifest");
    let assertions = first_manifest["assertions"]
        .as_object()
        .expect("assertions should be object");

    // Count ingredient assertions
    let ingredient_count = assertions
        .keys()
        .filter(|k| k.starts_with("c2pa.ingredient"))
        .count();

    // CA.jpg has 1 ingredient (A.jpg as parent)
    assert_eq!(
        ingredient_count, 1,
        "Should have exactly 1 ingredient assertion"
    );

    Ok(())
}

#[test]
fn test_ingredient_referenced_in_claim() -> Result<()> {
    let reader = Reader::default().with_stream("image/jpeg", Cursor::new(IMAGE_WITH_INGREDIENT))?;
    let json_value = reader.to_crjson_value()?;

    // Get manifests array
    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    // Find a manifest with assertions: either claim.v2 (created/gathered) or claim v1 (assertions array)
    let active_manifest = manifests
        .iter()
        .find(|m| {
            if let Some(claim_v2) = m.get("claim.v2") {
                let has_created = claim_v2
                    .get("created_assertions")
                    .and_then(|a| a.as_array())
                    .map(|a| !a.is_empty())
                    .unwrap_or(false);
                let has_gathered = claim_v2
                    .get("gathered_assertions")
                    .and_then(|a| a.as_array())
                    .map(|a| !a.is_empty())
                    .unwrap_or(false);
                has_created || has_gathered
            } else if let Some(claim_v1) = m.get("claim") {
                claim_v1
                    .get("assertions")
                    .and_then(|a| a.as_array())
                    .map(|a| !a.is_empty())
                    .unwrap_or(false)
            } else {
                false
            }
        })
        .expect("should have at least one manifest with assertions");

    // Check if ingredient is referenced in created_assertions (v2) or assertions (v1)
    let (created_assertions, gathered_assertions) =
        if let Some(claim_v2) = active_manifest.get("claim.v2").and_then(|v| v.as_object()) {
            (
                claim_v2["created_assertions"]
                    .as_array()
                    .expect("created_assertions should be array"),
                claim_v2["gathered_assertions"]
                    .as_array()
                    .expect("gathered_assertions should be array"),
            )
        } else {
            // V1: single "assertions" array; treat as both created and gathered for this check
            let assertions = active_manifest
                .get("claim")
                .and_then(|c| c.get("assertions"))
                .and_then(|a| a.as_array())
                .expect("claim.assertions should be array");
            (assertions, assertions)
        };

    // Find ingredient reference in EITHER created or gathered
    let has_ingredient_in_created = created_assertions.iter().any(|assertion_ref| {
        if let Some(url) = assertion_ref.get("url") {
            url.as_str()
                .map(|s| s.contains("c2pa.ingredient"))
                .unwrap_or(false)
        } else {
            false
        }
    });

    let has_ingredient_in_gathered = gathered_assertions.iter().any(|assertion_ref| {
        if let Some(url) = assertion_ref.get("url") {
            url.as_str()
                .map(|s| s.contains("c2pa.ingredient"))
                .unwrap_or(false)
        } else {
            false
        }
    });

    // Ingredient should be in one or the other
    assert!(
        has_ingredient_in_created || has_ingredient_in_gathered,
        "Ingredient should be referenced in either created_assertions or gathered_assertions"
    );

    Ok(())
}

#[test]
fn test_ingredient_in_actions_parameter() -> Result<()> {
    let reader = Reader::default().with_stream("image/jpeg", Cursor::new(IMAGE_WITH_INGREDIENT))?;
    let json_value = reader.to_crjson_value()?;

    // Get manifests array
    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    let first_manifest = manifests
        .first()
        .expect("should have at least one manifest");
    let assertions = first_manifest["assertions"]
        .as_object()
        .expect("assertions should be object");

    // Check actions assertion for ingredient reference
    if let Some(actions_assertion) = assertions.get("c2pa.actions.v2") {
        let actions = actions_assertion["actions"]
            .as_array()
            .expect("actions should be array");

        // Find action with ingredient parameter
        let has_ingredient_param = actions.iter().any(|action| {
            action
                .get("parameters")
                .and_then(|p| p.get("ingredient"))
                .is_some()
        });

        assert!(
            has_ingredient_param,
            "At least one action should have ingredient parameter"
        );
    }

    Ok(())
}

#[test]
fn test_multiple_ingredients_have_instances() -> Result<()> {
    // Note: CA.jpg only has 1 ingredient, so this test verifies the instance logic
    // For files with multiple ingredients, they would be labeled:
    // c2pa.ingredient__1, c2pa.ingredient__2, etc.

    let reader = Reader::default().with_stream("image/jpeg", Cursor::new(IMAGE_WITH_INGREDIENT))?;
    let json_value = reader.to_crjson_value()?;

    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    let first_manifest = manifests
        .first()
        .expect("should have at least one manifest");
    let assertions = first_manifest["assertions"]
        .as_object()
        .expect("assertions should be object");

    // For single ingredient, should be just "c2pa.ingredient"
    assert!(
        assertions.contains_key("c2pa.ingredient"),
        "Single ingredient should be c2pa.ingredient without instance"
    );

    // Should NOT have instance suffix for single ingredient
    assert!(
        !assertions.contains_key("c2pa.ingredient__1"),
        "Single ingredient should not have instance number"
    );

    Ok(())
}

#[test]
fn test_ingredient_label_matches_version() -> Result<()> {
    let reader = Reader::default().with_stream("image/jpeg", Cursor::new(IMAGE_WITH_INGREDIENT))?;
    let json_value = reader.to_crjson_value()?;

    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    let first_manifest = manifests
        .first()
        .expect("should have at least one manifest");
    let assertions = first_manifest["assertions"]
        .as_object()
        .expect("assertions should be object");

    // Get the ingredient assertion (could be c2pa.ingredient, c2pa.ingredient.v2, or c2pa.ingredient.v3)
    let ingredient_key = assertions
        .keys()
        .find(|k| k.starts_with("c2pa.ingredient"))
        .expect("Should have an ingredient assertion");

    // Get the ingredient object
    let ingredient = &assertions[ingredient_key];
    let ingredient_obj = ingredient.as_object().expect("ingredient should be object");

    // Verify the label field is NOT present (it's redundant since the key is the label)
    assert!(
        !ingredient_obj.contains_key("label"),
        "Ingredient should not have redundant label field"
    );

    // Verify the key follows correct versioning pattern
    assert!(
        ingredient_key == "c2pa.ingredient" || ingredient_key.starts_with("c2pa.ingredient.v"),
        "Ingredient key should be c2pa.ingredient or c2pa.ingredient.v{{N}}"
    );

    Ok(())
}

#[test]
fn test_ingredient_manifest_reports_recorded_results() -> Result<()> {
    let reader =
        Reader::default().with_stream("image/jpeg", Cursor::new(IMAGE_WITH_INGREDIENT_MANIFEST))?;
    let json_value = reader.to_crjson_value()?;

    // every status recorded in the active manifest's ingredient assertion is
    // reported on the ingredient's manifest
    let ingredient = &json_value["manifests"][0]["assertions"]["c2pa.ingredient.v3"];
    let label = ingredient["activeManifest"]["url"]
        .as_str()
        .and_then(|url| url.strip_prefix("self#jumbf=/c2pa/"))
        .expect("ingredient should reference a manifest");
    let recorded = &ingredient["validationResults"]["activeManifest"];
    let reported = &manifest_by_label(&json_value, label)["validationResults"];
    for kind in ["success", "informational", "failure"] {
        let reported_kind = reported[kind]
            .as_array()
            .expect("reported codes should be array");
        for status in recorded[kind]
            .as_array()
            .expect("recorded codes should be array")
        {
            assert!(
                reported_kind.contains(status),
                "recorded {kind} status not reported: {status}"
            );
        }
    }

    // the read-time delta is merged on top
    assert!(
        reported["success"]
            .as_array()
            .expect("reported codes should be array")
            .iter()
            .any(|status| status["code"] == "ingredient.manifest.validated"),
        "read-time ingredient.manifest.validated should be reported"
    );

    Ok(())
}

#[test]
fn test_ingredient_manifest_reports_recorded_validation_status() -> Result<()> {
    // read-time validation finds the recorded mismatch again
    let reader = Reader::default().with_stream(
        "image/jpeg",
        Cursor::new(IMAGE_WITH_BAD_INGREDIENT_SIGNATURE),
    )?;
    let json_value = reader.to_crjson_value()?;
    let label = "contentauth:urn:uuid:bc347336-f111-4c34-82da-a970150c5490";
    let failures = &manifest_by_label(&json_value, label)["validationResults"]["failure"];
    assert!(failures
        .as_array()
        .expect("failure codes should be array")
        .iter()
        .any(|status| status["code"] == "claimSignature.mismatch"));
    Ok(())
}

#[test]
fn test_ingredient_manifest_reports_records_from_every_assertion() -> Result<()> {
    // M2 records M1 as untrusted, M3 records M1 as trusted
    let m1 = sign_with_ingredients(test_context(), &[])?;
    let m2 = sign_with_ingredients(untrusting_context()?, &[&m1])?;
    let m3 = sign_with_ingredients(test_context(), &[&m2, &m1])?;

    let codes = reported_codes(&m3, &m1)?;
    assert!(codes.contains(&"signingCredential.untrusted".into()));
    assert!(codes.contains(&"signingCredential.trusted".into()));
    Ok(())
}

#[test]
fn test_ingredient_manifest_reports_recorded_deltas() -> Result<()> {
    // M2 records M1 as trusted, M3 records M1 as untrusted in a delta on M2's
    // ingredient assertion
    let m1 = sign_with_ingredients(test_context(), &[])?;
    let m2 = sign_with_ingredients(test_context(), &[&m1])?;
    let m3 = sign_with_ingredients(untrusting_context()?, &[&m2])?;

    let codes = reported_codes(&m3, &m1)?;
    assert!(codes.contains(&"signingCredential.untrusted".into()));
    Ok(())
}

/// The test context without the test signing certificate's trust anchors.
fn untrusting_context() -> Result<Context> {
    let mut settings = test_settings();
    settings.trust.anchors = None;
    Context::new().with_settings(settings)
}

/// Sign a JPEG under `context` with each of `ingredients` as an ingredient.
fn sign_with_ingredients(context: Context, ingredients: &[&[u8]]) -> Result<Vec<u8>> {
    let mut builder = Builder::from_context(context);
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    for ingredient in ingredients {
        builder.add_ingredient_from_stream("{}", "image/jpeg", &mut Cursor::new(ingredient))?;
    }
    let mut source = Cursor::new(IMAGE_WITHOUT_MANIFEST);
    let mut output = Cursor::new(Vec::new());
    builder.sign(&test_signer(), "image/jpeg", &mut source, &mut output)?;
    Ok(output.into_inner())
}

/// The codes `asset`'s crJSON reports for `ingredient`'s manifest, read trusting.
fn reported_codes(asset: &[u8], ingredient: &[u8]) -> Result<Vec<Value>> {
    let reader =
        Reader::from_context(test_context()).with_stream("image/jpeg", Cursor::new(ingredient))?;
    let label = reader
        .active_label()
        .expect("ingredient should have a manifest");
    let json_value = Reader::from_context(test_context())
        .with_stream("image/jpeg", Cursor::new(asset))?
        .to_crjson_value()?;
    let results = &manifest_by_label(&json_value, label)["validationResults"];
    Ok(["success", "informational", "failure"]
        .iter()
        .flat_map(|kind| results[kind].as_array().expect("codes should be array"))
        .map(|status| status["code"].clone())
        .collect())
}

fn manifest_by_label<'a>(json_value: &'a Value, label: &str) -> &'a Value {
    json_value["manifests"]
        .as_array()
        .expect("manifests should be array")
        .iter()
        .find(|manifest| manifest["label"] == label)
        .expect("manifest should be reported")
}
