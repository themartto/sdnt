use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::validate::validate_domain;

#[derive(Deserialize)]
pub struct Query {
    domain: String,
}

#[derive(Serialize)]
pub struct WhoisResult {
    domain: String,
    server: String,
    raw: String,
}

pub async fn lookup(query: web::Query<Query>) -> HttpResponse {
    if let Err(e) = validate_domain(&query.domain) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": e }));
    }

    match fetch_whois(&query.domain).await {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

async fn whois_raw(server: &str, query: &str) -> anyhow::Result<String> {
    let mut stream = timeout(
        Duration::from_secs(10),
        TcpStream::connect(format!("{}:43", server)),
    )
    .await??;

    stream.write_all(format!("{}\r\n", query).as_bytes()).await?;

    let mut response = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut response)).await??;

    Ok(String::from_utf8_lossy(&response).into_owned())
}

fn parse_referral_server(response: &str) -> Option<String> {
    for line in response.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();
        if lower.starts_with("whois:") {
            return trimmed.split_whitespace().nth(1).map(|s| s.to_string());
        }
    }
    None
}

async fn fetch_whois(domain: &str) -> anyhow::Result<WhoisResult> {
    let iana_response = whois_raw("whois.iana.org", domain).await?;

    let whois_server = match parse_referral_server(&iana_response) {
        Some(server) => server,
        None => {
            return Ok(WhoisResult {
                domain: domain.to_string(),
                server: "whois.iana.org".to_string(),
                raw: iana_response,
            });
        }
    };

    let raw = whois_raw(&whois_server, domain)
        .await
        .unwrap_or(iana_response);

    Ok(WhoisResult {
        domain: domain.to_string(),
        server: whois_server,
        raw,
    })
}
