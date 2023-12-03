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
pub struct FlexBox {
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "layout")]
    pub layout: Layout,
    #[serde(rename = "flex", skip_serializing_if = "Option::is_none")]
    pub flex: Option<i32>,
    #[serde(rename = "contents")]
    pub contents: Vec<crate::models::FlexComponent>,
    #[serde(rename = "spacing", skip_serializing_if = "Option::is_none")]
    pub spacing: Option<String>,
    #[serde(rename = "margin", skip_serializing_if = "Option::is_none")]
    pub margin: Option<String>,
    #[serde(rename = "position", skip_serializing_if = "Option::is_none")]
    pub position: Option<Position>,
    #[serde(rename = "offsetTop", skip_serializing_if = "Option::is_none")]
    pub offset_top: Option<String>,
    #[serde(rename = "offsetBottom", skip_serializing_if = "Option::is_none")]
    pub offset_bottom: Option<String>,
    #[serde(rename = "offsetStart", skip_serializing_if = "Option::is_none")]
    pub offset_start: Option<String>,
    #[serde(rename = "offsetEnd", skip_serializing_if = "Option::is_none")]
    pub offset_end: Option<String>,
    #[serde(rename = "backgroundColor", skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    #[serde(rename = "borderColor", skip_serializing_if = "Option::is_none")]
    pub border_color: Option<String>,
    #[serde(rename = "borderWidth", skip_serializing_if = "Option::is_none")]
    pub border_width: Option<String>,
    #[serde(rename = "cornerRadius", skip_serializing_if = "Option::is_none")]
    pub corner_radius: Option<String>,
    #[serde(rename = "width", skip_serializing_if = "Option::is_none")]
    pub width: Option<String>,
    #[serde(rename = "maxWidth", skip_serializing_if = "Option::is_none")]
    pub max_width: Option<String>,
    #[serde(rename = "height", skip_serializing_if = "Option::is_none")]
    pub height: Option<String>,
    #[serde(rename = "maxHeight", skip_serializing_if = "Option::is_none")]
    pub max_height: Option<String>,
    #[serde(rename = "paddingAll", skip_serializing_if = "Option::is_none")]
    pub padding_all: Option<String>,
    #[serde(rename = "paddingTop", skip_serializing_if = "Option::is_none")]
    pub padding_top: Option<String>,
    #[serde(rename = "paddingBottom", skip_serializing_if = "Option::is_none")]
    pub padding_bottom: Option<String>,
    #[serde(rename = "paddingStart", skip_serializing_if = "Option::is_none")]
    pub padding_start: Option<String>,
    #[serde(rename = "paddingEnd", skip_serializing_if = "Option::is_none")]
    pub padding_end: Option<String>,
    #[serde(rename = "action", skip_serializing_if = "Option::is_none")]
    pub action: Option<Box<crate::models::Action>>,
    #[serde(rename = "justifyContent", skip_serializing_if = "Option::is_none")]
    pub justify_content: Option<JustifyContent>,
    #[serde(rename = "alignItems", skip_serializing_if = "Option::is_none")]
    pub align_items: Option<AlignItems>,
    #[serde(rename = "background", skip_serializing_if = "Option::is_none")]
    pub background: Option<Box<crate::models::FlexBoxBackground>>,
}

impl FlexBox {
    pub fn new(
        r#type: String,
        layout: Layout,
        contents: Vec<crate::models::FlexComponent>,
    ) -> FlexBox {
        FlexBox {
            r#type,
            layout,
            flex: None,
            contents,
            spacing: None,
            margin: None,
            position: None,
            offset_top: None,
            offset_bottom: None,
            offset_start: None,
            offset_end: None,
            background_color: None,
            border_color: None,
            border_width: None,
            corner_radius: None,
            width: None,
            max_width: None,
            height: None,
            max_height: None,
            padding_all: None,
            padding_top: None,
            padding_bottom: None,
            padding_start: None,
            padding_end: None,
            action: None,
            justify_content: None,
            align_items: None,
            background: None,
        }
    }
}

///
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum Layout {
    #[serde(rename = "horizontal")]
    Horizontal,
    #[serde(rename = "vertical")]
    Vertical,
    #[serde(rename = "baseline")]
    Baseline,
}

impl Default for Layout {
    fn default() -> Layout {
        Self::Horizontal
    }
}
///
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum Position {
    #[serde(rename = "relative")]
    Relative,
    #[serde(rename = "absolute")]
    Absolute,
}

impl Default for Position {
    fn default() -> Position {
        Self::Relative
    }
}
///
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum JustifyContent {
    #[serde(rename = "center")]
    Center,
    #[serde(rename = "flex-start")]
    FlexStart,
    #[serde(rename = "flex-end")]
    FlexEnd,
    #[serde(rename = "space-between")]
    SpaceBetween,
    #[serde(rename = "space-around")]
    SpaceAround,
    #[serde(rename = "space-evenly")]
    SpaceEvenly,
}

impl Default for JustifyContent {
    fn default() -> JustifyContent {
        Self::Center
    }
}
///
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum AlignItems {
    #[serde(rename = "center")]
    Center,
    #[serde(rename = "flex-start")]
    FlexStart,
    #[serde(rename = "flex-end")]
    FlexEnd,
}

impl Default for AlignItems {
    fn default() -> AlignItems {
        Self::Center
    }
}
