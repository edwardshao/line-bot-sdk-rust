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
pub struct AudienceMatchMessagesRequest {
    /// Destination of the message (A value obtained by hashing the telephone number, which is another value normalized to E.164 format, with SHA256).
    #[serde(rename = "messages")]
    pub messages: Vec<crate::models::Message>,
    /// Message to send.
    #[serde(rename = "to")]
    pub to: Vec<String>,
    /// `true`: The user doesn’t receive a push notification when a message is sent. `false`: The user receives a push notification when the message is sent (unless they have disabled push notifications in LINE and/or their device). The default value is false.
    #[serde(
        rename = "notificationDisabled",
        skip_serializing_if = "Option::is_none"
    )]
    pub notification_disabled: Option<bool>,
}

impl AudienceMatchMessagesRequest {
    pub fn new(
        messages: Vec<crate::models::Message>,
        to: Vec<String>,
    ) -> AudienceMatchMessagesRequest {
        AudienceMatchMessagesRequest {
            messages,
            to,
            notification_disabled: None,
        }
    }
}
