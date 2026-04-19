use actix_web::{web, HttpResponse};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsConnector;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

use crate::validate::validate_domain;

#[derive(Deserialize)]
pub struct Query {
    domain: String,
}

#[derive(Serialize)]
pub struct CertInfo {
    subject: String,
    issuer: String,
    not_before: String,
    not_after: String,
    sans: Vec<String>,
    serial: String,
    is_expired: bool,
}

pub async fn lookup(
    query: web::Query<Query>,
    tls: web::Data<Arc<ClientConfig>>,
) -> HttpResponse {
    if let Err(e) = validate_domain(&query.domain) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": e }));
    }

    match fetch_cert(&query.domain, Arc::clone(&tls)).await {
        Ok(cert) => HttpResponse::Ok().json(cert),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

async fn fetch_cert(domain: &str, config: Arc<ClientConfig>) -> anyhow::Result<CertInfo> {
    let connector = TlsConnector::from(config);
    let server_name = ServerName::try_from(domain.to_string())?;

    let stream = timeout(
        Duration::from_secs(10),
        TcpStream::connect(format!("{}:443", domain)),
    )
    .await??;

    let tls_stream = timeout(
        Duration::from_secs(10),
        connector.connect(server_name, stream),
    )
    .await??;

    let (_, session) = tls_stream.get_ref();
    let certs = session
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("No certificates presented"))?;

    let der = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("Empty certificate chain"))?;

    let (_, cert) = X509Certificate::from_der(der.as_ref())?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let not_before = cert.validity().not_before.to_string();
    let not_after = cert.validity().not_after.to_string();
    let serial = cert.serial.to_string();

    let mut sans = Vec::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            match name {
                GeneralName::DNSName(s) => sans.push(s.to_string()),
                GeneralName::IPAddress(ip) => {
                    if ip.len() == 4 {
                        sans.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                    } else {
                        sans.push(
                            ip.chunks(2)
                                .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                                .collect::<Vec<_>>()
                                .join(":"),
                        );
                    }
                }
                _ => {}
            }
        }
    }

    let now = time::OffsetDateTime::now_utc();
    let is_expired = cert.validity().not_after.to_datetime() < now;

    Ok(CertInfo {
        subject,
        issuer,
        not_before,
        not_after,
        sans,
        serial,
        is_expired,
    })
}
