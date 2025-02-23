/*
* Copyright (C) 2016 LINE Corp.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

/*
 * Webhook Type Definition
 *
 * Webhook event definition of the LINE Messaging API
 *
 * The version of the OpenAPI document: 1.0.0
 *
 * Generated by: https://openapi-generator.tech
 */

/// LinkContent : Content of the account link event.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LinkContent {
    /// One of the following values to indicate whether linking the account was successful or not
    #[serde(rename = "result")]
    pub result: Result,
    /// Specified nonce (number used once) when verifying the user ID.
    #[serde(rename = "nonce")]
    pub nonce: String,
}

impl LinkContent {
    /// Content of the account link event.
    pub fn new(result: Result, nonce: String) -> LinkContent {
        LinkContent { result, nonce }
    }
}

/// One of the following values to indicate whether linking the account was successful or not
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum Result {
    #[serde(rename = "ok")]
    Ok,
    #[serde(rename = "failed")]
    Failed,
}

impl Default for Result {
    fn default() -> Result {
        Self::Ok
    }
}
