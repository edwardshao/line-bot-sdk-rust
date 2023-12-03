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
pub struct ErrorResponse {
    /// Message containing information about the error.
    #[serde(rename = "message")]
    pub message: String,
    /// An array of error details. If the array is empty, this property will not be included in the response.
    #[serde(rename = "details", skip_serializing_if = "Option::is_none")]
    pub details: Option<Vec<crate::models::ErrorDetail>>,
}

impl ErrorResponse {
    pub fn new(message: String) -> ErrorResponse {
        ErrorResponse {
            message,
            details: None,
        }
    }
}
