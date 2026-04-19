use actix_web::{web::Json, HttpRequest};
use serde::Serialize;

#[derive(Serialize)]
pub struct IpResponse {
    ip: String,
}

pub async fn lookup(req: HttpRequest) -> Json<IpResponse> {
    let ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    Json(IpResponse { ip })
}
