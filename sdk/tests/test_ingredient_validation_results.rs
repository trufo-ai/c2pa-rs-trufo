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

//! The validationResults the Builder records in v3 ingredient assertions.

mod common;

use std::io::Cursor;

use anyhow::Result;
use c2pa::{Builder, Context, Reader};
use common::{test_context, test_settings, test_signer};
use serde_json::json;

const SOURCE_IMAGE: &[u8] = include_bytes!("../tests/fixtures/no_manifest.jpg");
// a single manifest without ingredients, so validating it yields no deltas
const SINGLE_MANIFEST_IMAGE: &[u8] = include_bytes!("../tests/fixtures/C.jpg");
// a remote manifest, ingested without an activeManifest when fetching is off
const REMOTE_MANIFEST_IMAGE: &[u8] = include_bytes!("../tests/fixtures/cloud.jpg");

#[test]
fn test_ingredient_deltas_only_with_active_manifest() -> Result<()> {
    let mut settings = test_settings();
    settings.verify.remote_manifest_fetch = false;
    let mut builder = Builder::from_context(Context::new().with_settings(settings)?)
        .with_definition(json!({
            "assertions": [
                {"label": "c2pa.actions", "data": {"actions": [
                    {"action": "c2pa.created",
                     "digitalSourceType":
                        "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"}
                ]}}
            ]
        }))?;
    builder.add_ingredient_from_stream(
        json!({"title": "C.jpg", "relationship": "inputTo"}).to_string(),
        "image/jpeg",
        &mut Cursor::new(SINGLE_MANIFEST_IMAGE),
    )?;
    builder.add_ingredient_from_stream(
        json!({"title": "cloud.jpg", "relationship": "inputTo"}).to_string(),
        "image/jpeg",
        &mut Cursor::new(REMOTE_MANIFEST_IMAGE),
    )?;

    let mut dest = Cursor::new(Vec::new());
    builder.sign(
        &test_signer(),
        "image/jpeg",
        &mut Cursor::new(SOURCE_IMAGE),
        &mut dest,
    )?;

    dest.set_position(0);
    let reader = Reader::from_context(test_context()).with_stream("image/jpeg", &mut dest)?;
    let ingredients = reader
        .active_manifest()
        .expect("signed asset should have an active manifest")
        .ingredients();

    // C2PA spec 18.16.12.4.3: with an activeManifest, validationResults contain
    // ingredientDeltas, empty when there are none
    assert!(ingredients[0].active_manifest().is_some());
    let results = ingredients[0]
        .validation_results()
        .expect("C.jpg should record validationResults");
    assert_eq!(results.ingredient_deltas(), Some(&Vec::new()));

    // without one, the results recorded at ingest are left as they are
    assert!(ingredients[1].active_manifest().is_none());
    let results = ingredients[1]
        .validation_results()
        .expect("cloud.jpg should record validationResults");
    assert_eq!(results.ingredient_deltas(), None);
    Ok(())
}
