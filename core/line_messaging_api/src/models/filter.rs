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

/// Filter : Filter for narrowcast

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Filter {
    #[serde(rename = "demographic", skip_serializing_if = "Option::is_none")]
    pub demographic: Option<Box<crate::models::DemographicFilter>>,
}

impl Filter {
    /// Filter for narrowcast
    pub fn new() -> Filter {
        Filter { demographic: None }
    }
}
