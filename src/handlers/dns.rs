use actix_web::{web, HttpResponse};
use futures::future::join_all;
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    proto::rr::RecordType,
    TokioAsyncResolver,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;

use crate::config::Config;
use crate::validate::validate_domain;

#[derive(Deserialize)]
pub struct Query {
    domain: String,
    #[serde(rename = "type")]
    record_type: Option<String>,
}

#[derive(Serialize)]
pub struct ServerResult {
    location: String,
    server_ip: String,
    record_type: String,
    records: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub async fn lookup(query: web::Query<Query>, config: web::Data<Config>) -> HttpResponse {
    if let Err(e) = validate_domain(&query.domain) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": e }));
    }

    let raw_type = query.record_type.as_deref().unwrap_or("A").to_uppercase();

    let record_type = match parse_record_type(&raw_type) {
        Some(rt) => rt,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("unsupported record type: {}", raw_type),
                "supported": ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "CAA"]
            }));
        }
    };

    let domain = query.domain.trim_end_matches('.').to_string() + ".";

    let futures: Vec<_> = config.dns_servers.iter().map(|server| {
        let domain = domain.clone();
        let server_ip = server.ip.clone();
        let location = server.location.clone();
        let raw_type = raw_type.clone();
        async move {
            match query_server(&domain, &server_ip, record_type).await {
                Ok(records) => ServerResult {
                    location,
                    server_ip,
                    record_type: raw_type,
                    records,
                    error: None,
                },
                Err(e) => ServerResult {
                    location,
                    server_ip,
                    record_type: raw_type,
                    records: vec![],
                    error: Some(e.to_string()),
                },
            }
        }
    }).collect();

    HttpResponse::Ok().json(join_all(futures).await)
}

fn parse_record_type(s: &str) -> Option<RecordType> {
    match s {
        "A" => Some(RecordType::A),
        "AAAA" => Some(RecordType::AAAA),
        "MX" => Some(RecordType::MX),
        "NS" => Some(RecordType::NS),
        "TXT" => Some(RecordType::TXT),
        "CNAME" => Some(RecordType::CNAME),
        "SOA" => Some(RecordType::SOA),
        "PTR" => Some(RecordType::PTR),
        "SRV" => Some(RecordType::SRV),
        "CAA" => Some(RecordType::CAA),
        _ => None,
    }
}

async fn query_server(
    domain: &str,
    server_ip: &str,
    record_type: RecordType,
) -> anyhow::Result<Vec<String>> {
    let socket_addr: SocketAddr = format!("{}:53", server_ip).parse()?;

    let mut resolver_config = ResolverConfig::new();
    resolver_config.add_name_server(NameServerConfig::new(socket_addr, Protocol::Udp));

    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 1;

    let resolver = TokioAsyncResolver::tokio(resolver_config, opts);
    let response = resolver.lookup(domain, record_type).await?;

    Ok(response.record_iter().filter_map(|r| r.data().map(|d| d.to_string())).collect())
}
