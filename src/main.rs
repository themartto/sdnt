use actix_web::{web, App, HttpServer};
use actix_cors::Cors;
use actix_governor::{Governor, GovernorConfigBuilder};
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;

mod config;
mod handlers;
mod validate;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let cfg = config::load().expect("Failed to load config.toml");
    let host = cfg.server.host.clone();
    let port = cfg.server.port;
    let data = web::Data::new(cfg);

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config: web::Data<Arc<ClientConfig>> = web::Data::new(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    ));

    println!("Listening on {}:{}", host, port);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);
        
        let governor_conf = GovernorConfigBuilder::default()
            .seconds_per_request(1)
            .burst_size(5)
            .finish()
            .expect("Invalid auth rate limiter configuration");

        App::new()
            .wrap(cors)
            .wrap(Governor::new(&governor_conf))
            .app_data(data.clone())
            .app_data(tls_config.clone())
            .route("/dns", web::get().to(handlers::dns::lookup))
            .route("/whois", web::get().to(handlers::whois::lookup))
            .route("/ssl", web::get().to(handlers::ssl::lookup))
            .route("/ip", web::get().to(handlers::ip::lookup))
    })
    .bind((host.as_str(), port))?
    .run()
    .await
}
