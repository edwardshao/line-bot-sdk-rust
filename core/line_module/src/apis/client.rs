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

use std::sync::Arc;

use super::configuration::Configuration;
use hyper;

pub struct APIClient {
    line_module_api: Box<dyn crate::apis::LineModuleApi>,
}

impl APIClient {
    pub fn new<C: hyper::client::connect::Connect>(configuration: Configuration<C>) -> APIClient
    where
        C: Clone + std::marker::Send + Sync + 'static,
    {
        let arc = Arc::new(configuration);

        APIClient {
            line_module_api: Box::new(crate::apis::LineModuleApiClient::new(arc.clone())),
        }
    }

    pub fn line_module_api(&self) -> &dyn crate::apis::LineModuleApi {
        self.line_module_api.as_ref()
    }
}
