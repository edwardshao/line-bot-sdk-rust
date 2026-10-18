/*
* Copyright 2023 nanato12
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

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper::client::connect::{Connected, Connection, HttpConnector};
use hyper::Uri;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tower_service::Service;

pub struct HttpsStream<T>(pub TlsStream<T>);

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for HttpsStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for HttpsStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl<T: Connection + AsyncRead + AsyncWrite + Unpin> Connection for HttpsStream<T> {
    fn connected(&self) -> Connected {
        let (tcp, _) = self.0.get_ref();
        tcp.connected()
    }
}

#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    tls: TlsConnector,
}

impl<T> HttpsConnector<T> {
    pub fn new(http: T, config: Arc<ClientConfig>) -> Self {
        Self {
            http,
            tls: TlsConnector::from(config),
        }
    }
}

impl<T> Service<Uri> for HttpsConnector<T>
where
    T: Service<Uri> + Clone + Send + 'static,
    T::Response: Connection + AsyncRead + AsyncWrite + Send + Unpin + 'static,
    T::Future: Send + 'static,
    T::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = HttpsStream<T::Response>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let hostname = dst.host().unwrap_or_default().to_string();
        let connecting_http = self.http.call(dst);
        let tls = self.tls.clone();

        Box::pin(async move {
            let tcp = connecting_http.await.map_err(Into::into)?;
            let server_name = ServerName::try_from(hostname.as_str())
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid DNS name {}: {}", hostname, e),
                    )
                })?
                .to_owned();
            let tls_stream = tls.connect(server_name, tcp).await?;
            Ok(HttpsStream(tls_stream))
        })
    }
}

#[derive(Default)]
pub struct HttpsConnectorBuilder;

impl HttpsConnectorBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn with_native_roots(self) -> Self {
        self
    }

    pub fn https_only(self) -> Self {
        self
    }

    pub fn enable_http1(self) -> Self {
        self
    }

    pub fn build(self) -> HttpsConnector<HttpConnector> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);

        let mut root_store = RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = root_store.add(cert);
        }
        if root_store.is_empty() {
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        let config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("valid protocol versions")
        .with_root_certificates(root_store)
        .with_no_client_auth();

        HttpsConnector::new(http, Arc::new(config))
    }
}
