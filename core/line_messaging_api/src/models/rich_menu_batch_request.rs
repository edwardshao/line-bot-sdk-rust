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
 * LINE Messaging API
 *
 * This document describes LINE Messaging API.
 *
 * The version of the OpenAPI document: 0.0.1
 *
 * Generated by: https://openapi-generator.tech
 */

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RichMenuBatchRequest {
    /// Array of Rich menu operation object...
    #[serde(rename = "operations")]
    pub operations: Vec<crate::models::RichMenuBatchOperation>,
    /// Key for retry. Key value is a string matching the regular expression pattern
    #[serde(rename = "resumeRequestKey", skip_serializing_if = "Option::is_none")]
    pub resume_request_key: Option<String>,
}

impl RichMenuBatchRequest {
    pub fn new(operations: Vec<crate::models::RichMenuBatchOperation>) -> RichMenuBatchRequest {
        RichMenuBatchRequest {
            operations,
            resume_request_key: None,
        }
    }
}
