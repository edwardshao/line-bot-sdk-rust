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

use std::borrow::Borrow;
#[allow(unused_imports)]
use std::option::Option;
use std::pin::Pin;
use std::sync::Arc;

use futures::Future;
use hyper;

use super::request as __internal_request;
use super::{configuration, Error};

pub struct DummyApiClient<C: hyper::client::connect::Connect>
where
    C: Clone + std::marker::Send + Sync + 'static,
{
    configuration: Arc<configuration::Configuration<C>>,
}

impl<C: hyper::client::connect::Connect> DummyApiClient<C>
where
    C: Clone + std::marker::Send + Sync,
{
    pub fn new(configuration: Arc<configuration::Configuration<C>>) -> DummyApiClient<C> {
        DummyApiClient { configuration }
    }
}

pub trait DummyApi {
    fn callback(
        &self,
        callback_request: crate::models::CallbackRequest,
    ) -> Pin<Box<dyn Future<Output = Result<String, Error>>>>;
}

impl<C: hyper::client::connect::Connect> DummyApi for DummyApiClient<C>
where
    C: Clone + std::marker::Send + Sync,
{
    #[allow(unused_mut)]
    fn callback(
        &self,
        callback_request: crate::models::CallbackRequest,
    ) -> Pin<Box<dyn Future<Output = Result<String, Error>>>> {
        let mut req =
            __internal_request::Request::new(hyper::Method::POST, "/callback".to_string());
        req = req.with_body_param(callback_request);

        req.execute(self.configuration.borrow())
    }
}
