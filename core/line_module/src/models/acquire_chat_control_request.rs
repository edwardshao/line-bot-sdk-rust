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

/// AcquireChatControlRequest : Request entity of the Acquire Control API

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AcquireChatControlRequest {
    /// `True`: After the time limit (ttl) has passed, the initiative (Chat Control) will return to the Primary Channel. (Default) `False`: There's no time limit and the initiative (Chat Control) doesn't change over time.
    #[serde(rename = "expired", skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    /// The time it takes for initiative (Chat Control) to return to the Primary Channel (the time that the module channel stays on the Active Channel). The value is specified in seconds. The maximum value is one year (3600 * 24 * 365). The default value is 3600 (1 hour).  * Ignored if the value of expired is false.
    #[serde(rename = "ttl", skip_serializing_if = "Option::is_none")]
    pub ttl: Option<i32>,
}

impl AcquireChatControlRequest {
    /// Request entity of the Acquire Control API
    pub fn new() -> AcquireChatControlRequest {
        AcquireChatControlRequest {
            expired: None,
            ttl: None,
        }
    }
}
