use anyhow::Result;

use rmcp::transport::{
    stdio,
    streamable_http_server::{StreamableHttpService, session::local::LocalSessionManager},
};

use rmcp::ServiceExt;

pub mod tools;

#[tokio::main]
async fn main() -> Result<()> {
    if cfg!(feature = "http_service") {
        let service = StreamableHttpService::new(
            || Ok(tools::BpfToolHandler::new()),
            LocalSessionManager::default().into(),
            Default::default(),
        );

        let router = axum::Router::new().nest_service("/mcp", service);
        let tcp = tokio::net::TcpListener::bind("0.0.0.0:1337").await?;
        let _ = axum::serve(tcp, router)
            .with_graceful_shutdown(async { tokio::signal::ctrl_c().await.unwrap() })
            .await;
    } else {
        let service = tools::BpfToolHandler::new().serve(stdio()).await?;
        service.waiting().await?;
    }

    Ok(())
}
