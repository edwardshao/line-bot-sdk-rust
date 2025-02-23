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
pub struct PostbackAction {
    /// Type of action
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// Label for the action.
    #[serde(rename = "label", skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(rename = "data", skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(rename = "displayText", skip_serializing_if = "Option::is_none")]
    pub display_text: Option<String>,
    #[serde(rename = "text", skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(rename = "inputOption", skip_serializing_if = "Option::is_none")]
    pub input_option: Option<InputOption>,
    #[serde(rename = "fillInText", skip_serializing_if = "Option::is_none")]
    pub fill_in_text: Option<String>,
}

impl PostbackAction {
    pub fn new() -> PostbackAction {
        PostbackAction {
            r#type: None,
            label: None,
            data: None,
            display_text: None,
            text: None,
            input_option: None,
            fill_in_text: None,
        }
    }
}

///
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum InputOption {
    #[serde(rename = "closeRichMenu")]
    CloseRichMenu,
    #[serde(rename = "openRichMenu")]
    OpenRichMenu,
    #[serde(rename = "openKeyboard")]
    OpenKeyboard,
    #[serde(rename = "openVoice")]
    OpenVoice,
}

impl Default for InputOption {
    fn default() -> InputOption {
        Self::CloseRichMenu
    }
}
