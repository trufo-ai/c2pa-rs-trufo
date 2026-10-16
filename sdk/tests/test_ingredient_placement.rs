// Copyright 2026 Trufo, Inc. All rights reserved.
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

//! Per-ingredient claim-list placement (the ingredient definition's `created` field).

mod common;

use std::io::Cursor;

use anyhow::Result;
use c2pa::{Builder, Context, Reader};
use common::{test_context, test_settings, test_signer};
use serde_json::{json, Value};

const TEST_IMAGE: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");

/// Returns a builder with the given created_assertion_labels setting whose
/// definition holds the given ingredients.
fn placement_builder(created_labels: &[&str], ingredients: Value) -> Result<Builder> {
    let mut settings = test_settings();
    settings.builder.created_assertion_labels = Some(
        created_labels
            .iter()
            .map(|label| label.to_string())
            .collect(),
    );
    let definition = json!({
        "title": "placement.jpg",
        "format": "image/jpeg",
        "ingredients": ingredients,
        "assertions": [
            {"label": "c2pa.actions", "data": {"actions": [
                {"action": "c2pa.created",
                 "digitalSourceType":
                    "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"}
            ]}}
        ]
    });
    Ok(
        Builder::from_context(Context::new().with_settings(settings)?)
            .with_definition(definition)?,
    )
}

/// Signs the builder's manifest and returns the ingredient assertion labels in
/// its created and gathered claim lists.
fn sign_and_read_ingredient_lists(builder: &mut Builder) -> Result<(Vec<String>, Vec<String>)> {
    let mut dest = Cursor::new(Vec::new());
    builder.sign(
        &test_signer(),
        "image/jpeg",
        &mut Cursor::new(TEST_IMAGE),
        &mut dest,
    )?;

    dest.set_position(0);
    let reader = Reader::from_context(test_context()).with_stream("image/jpeg", &mut dest)?;
    let crjson = reader.to_crjson_value()?;
    let claim = &crjson["manifests"][0]["claim.v2"];
    let ingredient_labels = |key: &str| -> Vec<String> {
        claim[key]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|entry| entry["url"].as_str()?.rsplit_once('/'))
            .map(|(_, label)| label.to_string())
            .filter(|label| label.starts_with("c2pa.ingredient"))
            .collect()
    };
    Ok((
        ingredient_labels("created_assertions"),
        ingredient_labels("gathered_assertions"),
    ))
}

#[test]
fn test_per_ingredient_placement() -> Result<()> {
    // the bridge's configuration: ingredients are created unless declared gathered
    let mut builder = placement_builder(
        &["c2pa.ingredient"],
        json!([
            {"title": "unset.jpg", "relationship": "inputTo"},
            {"title": "declared.jpg", "relationship": "inputTo", "created": false}
        ]),
    )?;
    let (created, gathered) = sign_and_read_ingredient_lists(&mut builder)?;
    assert_eq!(created, ["c2pa.ingredient.v3"]);
    assert_eq!(gathered, ["c2pa.ingredient.v3__1"]);

    // without c2pa.ingredient in the labels, a declared created ingredient is created
    let mut builder = placement_builder(
        &[],
        json!([{"title": "witnessed.jpg", "relationship": "inputTo", "created": true}]),
    )?;
    let (created, gathered) = sign_and_read_ingredient_lists(&mut builder)?;
    assert_eq!(created, ["c2pa.ingredient.v3"]);
    assert!(gathered.is_empty(), "gathered: {gathered:?}");
    Ok(())
}
