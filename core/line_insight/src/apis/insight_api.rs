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
 * LINE Messaging API(Insight)
 *
 * This document describes LINE Messaging API(Insight).
 *
 * The version of the OpenAPI document: 0.0.1
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

pub struct InsightApiClient<C: hyper::client::connect::Connect>
where
    C: Clone + std::marker::Send + Sync + 'static,
{
    configuration: Arc<configuration::Configuration<C>>,
}

impl<C: hyper::client::connect::Connect> InsightApiClient<C>
where
    C: Clone + std::marker::Send + Sync,
{
    pub fn new(configuration: Arc<configuration::Configuration<C>>) -> InsightApiClient<C> {
        InsightApiClient { configuration }
    }
}

pub trait InsightApi {
    fn get_friends_demographics(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<crate::models::GetFriendsDemographicsResponse, Error>>>>;
    fn get_message_event(
        &self,
        request_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<crate::models::GetMessageEventResponse, Error>>>>;
    fn get_number_of_followers(
        &self,
        date: Option<&str>,
    ) -> Pin<Box<dyn Future<Output = Result<crate::models::GetNumberOfFollowersResponse, Error>>>>;
    fn get_number_of_message_deliveries(
        &self,
        date: &str,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<crate::models::GetNumberOfMessageDeliveriesResponse, Error>>,
        >,
    >;
    fn get_statistics_per_unit(
        &self,
        custom_aggregation_unit: &str,
        from: &str,
        to: &str,
    ) -> Pin<Box<dyn Future<Output = Result<crate::models::GetStatisticsPerUnitResponse, Error>>>>;
}

impl<C: hyper::client::connect::Connect> InsightApi for InsightApiClient<C>
where
    C: Clone + std::marker::Send + Sync,
{
    #[allow(unused_mut)]
    fn get_friends_demographics(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<crate::models::GetFriendsDemographicsResponse, Error>>>>
    {
        let mut req = __internal_request::Request::new(
            hyper::Method::GET,
            "/v2/bot/insight/demographic".to_string(),
        );

        req.execute(self.configuration.borrow())
    }

    #[allow(unused_mut)]
    fn get_message_event(
        &self,
        request_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<crate::models::GetMessageEventResponse, Error>>>> {
        let mut req = __internal_request::Request::new(
            hyper::Method::GET,
            "/v2/bot/insight/message/event".to_string(),
        );
        req = req.with_query_param("requestId".to_string(), request_id.to_string());

        req.execute(self.configuration.borrow())
    }

    #[allow(unused_mut)]
    fn get_number_of_followers(
        &self,
        date: Option<&str>,
    ) -> Pin<Box<dyn Future<Output = Result<crate::models::GetNumberOfFollowersResponse, Error>>>>
    {
        let mut req = __internal_request::Request::new(
            hyper::Method::GET,
            "/v2/bot/insight/followers".to_string(),
        );
        if let Some(ref s) = date {
            let query_value = s.to_string();
            req = req.with_query_param("date".to_string(), query_value);
        }

        req.execute(self.configuration.borrow())
    }

    #[allow(unused_mut)]
    fn get_number_of_message_deliveries(
        &self,
        date: &str,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<crate::models::GetNumberOfMessageDeliveriesResponse, Error>>,
        >,
    > {
        let mut req = __internal_request::Request::new(
            hyper::Method::GET,
            "/v2/bot/insight/message/delivery".to_string(),
        );
        req = req.with_query_param("date".to_string(), date.to_string());

        req.execute(self.configuration.borrow())
    }

    #[allow(unused_mut)]
    fn get_statistics_per_unit(
        &self,
        custom_aggregation_unit: &str,
        from: &str,
        to: &str,
    ) -> Pin<Box<dyn Future<Output = Result<crate::models::GetStatisticsPerUnitResponse, Error>>>>
    {
        let mut req = __internal_request::Request::new(
            hyper::Method::GET,
            "/v2/bot/insight/message/event/aggregation".to_string(),
        );
        req = req.with_query_param(
            "customAggregationUnit".to_string(),
            custom_aggregation_unit.to_string(),
        );
        req = req.with_query_param("from".to_string(), from.to_string());
        req = req.with_query_param("to".to_string(), to.to_string());

        req.execute(self.configuration.borrow())
    }
}
