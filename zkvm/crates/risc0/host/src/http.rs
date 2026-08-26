//! The `/v5` HTTP proof service.
//!
//! One local CUDA proof runs at a time and every `/v5/*` route is behind the
//! configured shared secret; `/healthz`, `/v5/capabilities` and `/metrics`
//! stay open so an orchestrator can observe readiness and scrape counters.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{bail, Context, Result};

use crate::capabilities::{cmd_capabilities, cmd_health};
use crate::commands_v5::{
    cmd_execute_cold_template_v5, cmd_execute_room_v5, cmd_prepare_room_v5,
    cmd_prove_cold_template_v5, cmd_prove_room_v5, cmd_verify_cold_template_v5, cmd_verify_room_v5,
};
use crate::gpu::gpu_metrics_sample;
use crate::hosting::{
    cmd_execute_aggregate_v1, cmd_execute_data_availability_v1,
    cmd_prepare_data_availability_v1, cmd_prove_aggregate_v1,
    cmd_prove_data_availability_v1, cmd_verify_aggregate_v1,
    cmd_verify_data_availability_v1,
};
use crate::report::safe_failure_reason;
use crate::live_prepare::cmd_prepare_live_room_batch;
use crate::wrap_v5::{
    cmd_wrap_groth16_from_p254_v5, cmd_wrap_groth16_v5, cmd_wrap_identity_p254_v5,
};

const MAX_HTTP_BODY_BYTES_V5: usize =
    8 * stf_types::MAX_BATCH_WITNESS_BYTES_V4 + 8 * 1024 * 1024;

#[derive(Clone)]
struct HttpStateV5 {
    /// One local CUDA prover job at a time. This prevents concurrent requests
    /// from silently spilling or OOMing VRAM and gives the benchmark harness
    /// an honest queue instead of an accidental resource race.
    gpu_gate: Arc<tokio::sync::Semaphore>,
    /// Shared secret required on every `/v5/*` route, read from
    /// `ZKDEAL_PROVER_TOKEN` at startup. `None` leaves the routes open, which
    /// is only defensible on a loopback bind.
    token: Option<Arc<String>>,
    /// Uptime and per-route request counters served on the unauthenticated
    /// `/metrics` route. `Arc`-shared so every handler clone bumps one map.
    metrics: Arc<HttpMetricsV5>,
}

/// Process-lifetime observability state behind `/metrics`. Counters are keyed
/// by `'static` route and outcome literals so the render step never has to
/// escape a label value.
struct HttpMetricsV5 {
    started: Instant,
    requests: Mutex<BTreeMap<(&'static str, &'static str), u64>>,
}

impl HttpMetricsV5 {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            requests: Mutex::new(BTreeMap::new()),
        }
    }

    fn record(&self, route: &'static str, outcome: &'static str) {
        if let Ok(mut requests) = self.requests.lock() {
            *requests.entry((route, outcome)).or_insert(0) += 1;
        }
    }
}

/// Constant-time bearer-token check. Every `/v5/*` route runs a proof job on
/// the single GPU slot, so an unauthenticated caller can starve every room
/// this prover serves.
fn authorized_v5(expected: Option<&str>, headers: &axum::http::HeaderMap) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    let Some(presented) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    let expected = expected.as_bytes();
    let presented = presented.as_bytes();
    let mut difference = u8::from(expected.len() != presented.len());
    for (index, byte) in expected.iter().enumerate() {
        difference |= byte ^ presented.get(index).copied().unwrap_or(0);
    }
    difference == 0
}

async fn http_command_v5(
    state: HttpStateV5,
    route: &'static str,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
    command: fn(&str) -> Result<serde_json::Value>,
    needs_gpu: bool,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    if !authorized_v5(state.token.as_deref().map(String::as_str), &headers) {
        state.metrics.record(route, "unauthorized");
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({
                "decision": "request-rejected",
                "reason": "missing or invalid prover bearer token",
                "effect": "no proof or valid transition was produced",
                "recovery": "present the shared secret configured in ZKDEAL_PROVER_TOKEN"
            })),
        )
            .into_response();
    }
    let raw = match String::from_utf8(body.to_vec()) {
        Ok(raw) => raw,
        Err(_) => {
            state.metrics.record(route, "rejected");
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({ "error": "request body is not UTF-8 JSON" })),
            )
                .into_response();
        }
    };
    // The CPU-only execute/verify routes must not serialise behind the GPU
    // slot: taking the permit there lets a cheap request block a real proof.
    let permit = if needs_gpu {
        match state.gpu_gate.acquire_owned().await {
            Ok(permit) => Some(permit),
            Err(_) => {
                state.metrics.record(route, "error");
                return (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    axum::Json(serde_json::json!({ "error": "prover is shutting down" })),
                )
                    .into_response();
            }
        }
    } else {
        None
    };
    let result = tokio::task::spawn_blocking(move || command(&raw)).await;
    drop(permit);
    match result {
        Ok(Ok(value)) => {
            state.metrics.record(route, "ok");
            axum::Json(value).into_response()
        }
        Ok(Err(error)) => {
            state.metrics.record(route, "rejected");
            (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "decision": "request-rejected",
                    "reason": safe_failure_reason(&error),
                    "effect": "no proof or valid transition was produced",
                    "recovery": "check the witness, pinned program and CUDA readiness"
                })),
            )
                .into_response()
        }
        Err(_) => {
            state.metrics.record(route, "error");
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({
                    "decision": "prover-task-failed",
                    "effect": "no proof was produced",
                    "recovery": "inspect the private evidence log and retry"
                })),
            )
                .into_response()
        }
    }
}

macro_rules! http_handler {
    ($name:ident, $route:literal, $command:ident, $needs_gpu:expr) => {
        async fn $name(
            axum::extract::State(state): axum::extract::State<HttpStateV5>,
            headers: axum::http::HeaderMap,
            body: axum::body::Bytes,
        ) -> axum::response::Response {
            http_command_v5(state, $route, headers, body, $command, $needs_gpu).await
        }
    };
}

http_handler!(
    http_execute_room_v5,
    "/v5/rooms/execute",
    cmd_execute_room_v5,
    false
);
http_handler!(
    http_prepare_room_v5,
    "/v5/rooms/prepare",
    cmd_prepare_room_v5,
    true
);
http_handler!(
    http_prepare_live_room_batch,
    "/hosting/v1/rooms/prepare-batch",
    cmd_prepare_live_room_batch,
    false
);
http_handler!(
    http_prove_room_v5,
    "/v5/rooms/prove",
    cmd_prove_room_v5,
    true
);
http_handler!(
    http_verify_room_v5,
    "/v5/rooms/verify",
    cmd_verify_room_v5,
    false
);
http_handler!(
    http_execute_cold_template_v5,
    "/v5/cold-templates/execute",
    cmd_execute_cold_template_v5,
    false
);
http_handler!(
    http_prove_cold_template_v5,
    "/v5/cold-templates/prove",
    cmd_prove_cold_template_v5,
    true
);
http_handler!(
    http_verify_cold_template_v5,
    "/v5/cold-templates/verify",
    cmd_verify_cold_template_v5,
    false
);
http_handler!(
    http_prepare_data_availability_v1,
    "/v5/data-availability/prepare",
    cmd_prepare_data_availability_v1,
    false
);
http_handler!(
    http_execute_data_availability_v1,
    "/v5/data-availability/execute",
    cmd_execute_data_availability_v1,
    false
);
http_handler!(
    http_prove_data_availability_v1,
    "/v5/data-availability/prove",
    cmd_prove_data_availability_v1,
    true
);
http_handler!(
    http_verify_data_availability_v1,
    "/v5/data-availability/verify",
    cmd_verify_data_availability_v1,
    false
);
http_handler!(
    http_execute_aggregate_v1,
    "/v5/aggregates/execute",
    cmd_execute_aggregate_v1,
    false
);
http_handler!(
    http_prove_aggregate_v1,
    "/v5/aggregates/prove",
    cmd_prove_aggregate_v1,
    true
);
http_handler!(
    http_verify_aggregate_v1,
    "/v5/aggregates/verify",
    cmd_verify_aggregate_v1,
    false
);
http_handler!(
    http_wrap_groth16_v5,
    "/v5/receipts/wrap",
    cmd_wrap_groth16_v5,
    true
);
http_handler!(
    http_wrap_identity_p254_v5,
    "/v5/receipts/identity-p254",
    cmd_wrap_identity_p254_v5,
    true
);
http_handler!(
    http_wrap_groth16_from_p254_v5,
    "/v5/receipts/groth16",
    cmd_wrap_groth16_from_p254_v5,
    true
);

/// Deliberately not `spawn_blocking`: the runtime is built with
/// `max_blocking_threads(1)` and a proof owns that thread for minutes, so
/// queueing readiness behind it would let an in-flight proof fail the
/// orchestrator's health check. `nvidia_query` caches the GPU probe instead,
/// which is what made this handler blocking in the first place.
async fn http_health_v5() -> axum::response::Response {
    use axum::response::IntoResponse as _;
    match cmd_health() {
        Ok(value) => axum::Json(value).into_response(),
        Err(error) => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "status": "not-ready",
                "reason": safe_failure_reason(&error),
                "effect": "proof requests are unavailable",
                "recovery": "restore the pinned CUDA runtime and retry"
            })),
        )
            .into_response(),
    }
}

async fn http_capabilities_v5() -> axum::Json<serde_json::Value> {
    axum::Json(cmd_capabilities())
}

/// Deliberately not `spawn_blocking`, for the same reason as `/healthz`
/// above: the runtime has `max_blocking_threads(1)`, an in-flight proof owns
/// that thread for minutes, and a scrape must never queue behind it.
/// `gpu_metrics_sample` reads the TTL-cached driver probe instead of
/// spawning `nvidia-smi` per request. The route stays unauthenticated next
/// to `/healthz` because it serves only aggregate counters and driver
/// gauges; witness, request or receipt bytes must never be rendered here.
async fn http_metrics_v5(
    axum::extract::State(state): axum::extract::State<HttpStateV5>,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        render_metrics_v5(&state.metrics, gpu_metrics_sample()),
    )
        .into_response()
}

/// Prometheus text format 0.0.4, rendered by hand so the prover gains no new
/// dependency. Label values are the `'static` literals passed to
/// `HttpMetricsV5::record` and are not escaped, so request-derived text must
/// never be interpolated into a label.
fn render_metrics_v5(metrics: &HttpMetricsV5, gpu: Option<(f64, f64, f64)>) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    out.push_str("# HELP zkdeal_prover_uptime_seconds Seconds since the prover HTTP service started.\n");
    out.push_str("# TYPE zkdeal_prover_uptime_seconds gauge\n");
    let _ = writeln!(
        out,
        "zkdeal_prover_uptime_seconds {}",
        metrics.started.elapsed().as_secs_f64()
    );
    out.push_str("# HELP zkdeal_prover_requests_total HTTP requests observed per route and outcome.\n");
    out.push_str("# TYPE zkdeal_prover_requests_total counter\n");
    if let Ok(requests) = metrics.requests.lock() {
        for ((route, outcome), count) in requests.iter() {
            let _ = writeln!(
                out,
                "zkdeal_prover_requests_total{{route=\"{route}\",outcome=\"{outcome}\"}} {count}"
            );
        }
    }
    if let Some((utilization_percent, memory_used_mib, power_watts)) = gpu {
        out.push_str("# HELP zkdeal_prover_gpu_utilization_percent GPU utilization reported by the NVIDIA driver.\n");
        out.push_str("# TYPE zkdeal_prover_gpu_utilization_percent gauge\n");
        let _ = writeln!(out, "zkdeal_prover_gpu_utilization_percent {utilization_percent}");
        out.push_str("# HELP zkdeal_prover_gpu_memory_used_mib GPU memory in use, in MiB.\n");
        out.push_str("# TYPE zkdeal_prover_gpu_memory_used_mib gauge\n");
        let _ = writeln!(out, "zkdeal_prover_gpu_memory_used_mib {memory_used_mib}");
        out.push_str("# HELP zkdeal_prover_gpu_power_watts GPU power draw reported by the NVIDIA driver.\n");
        out.push_str("# TYPE zkdeal_prover_gpu_power_watts gauge\n");
        let _ = writeln!(out, "zkdeal_prover_gpu_power_watts {power_watts}");
    }
    out
}

pub(crate) fn serve_v5() -> Result<()> {
    use axum::routing::{get, post};

    // A production prover must never become routable in a degraded CPU-only
    // state. The same check backs `/healthz`, but doing it before the listener
    // is bound makes missing CUDA support/GPU visibility a startup failure.
    cmd_health().context("CUDA prover startup preflight")?;

    // Every route on this service runs a proof job on a single GPU slot, so
    // the default reach is the local host. Widening it is an explicit
    // deployment decision made with `--host`.
    let mut host = "127.0.0.1".to_owned();
    let mut port = 8080u16;
    let args = std::env::args().skip(2).collect::<Vec<_>>();
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--host" => {
                index += 1;
                host = args.get(index).context("--host requires a value")?.clone();
            }
            "--port" => {
                index += 1;
                port = args
                    .get(index)
                    .context("--port requires a value")?
                    .parse()
                    .context("--port is not a u16")?;
            }
            other => bail!("unknown serve option '{other}'"),
        }
        index += 1;
    }
    let address = format!("{host}:{port}");
    let token = std::env::var("ZKDEAL_PROVER_TOKEN")
        .ok()
        .filter(|value| !value.is_empty());
    let loopback = host == "127.0.0.1" || host == "localhost" || host == "::1";
    if token.is_none() && !loopback {
        eprintln!(
            "Blocker: {address} is reachable off-host with no ZKDEAL_PROVER_TOKEN; every /v5 route is unauthenticated."
        );
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .context("build HTTP runtime")?;
    runtime.block_on(async move {
        let state = HttpStateV5 {
            gpu_gate: Arc::new(tokio::sync::Semaphore::new(1)),
            token: token.map(Arc::new),
            metrics: Arc::new(HttpMetricsV5::new()),
        };
        let app = axum::Router::new()
            .route("/healthz", get(http_health_v5))
            .route("/metrics", get(http_metrics_v5))
            .route("/v5/capabilities", get(http_capabilities_v5))
            .route("/v5/rooms/prepare", post(http_prepare_room_v5))
            .route(
                "/hosting/v1/rooms/prepare-batch",
                post(http_prepare_live_room_batch),
            )
            .route("/v5/rooms/execute", post(http_execute_room_v5))
            .route("/v5/rooms/prove", post(http_prove_room_v5))
            .route("/v5/rooms/verify", post(http_verify_room_v5))
            .route(
                "/v5/cold-templates/execute",
                post(http_execute_cold_template_v5),
            )
            .route(
                "/v5/cold-templates/prove",
                post(http_prove_cold_template_v5),
            )
            .route(
                "/v5/cold-templates/verify",
                post(http_verify_cold_template_v5),
            )
            .route(
                "/v5/data-availability/prepare",
                post(http_prepare_data_availability_v1),
            )
            .route(
                "/v5/data-availability/execute",
                post(http_execute_data_availability_v1),
            )
            .route(
                "/v5/data-availability/prove",
                post(http_prove_data_availability_v1),
            )
            .route(
                "/v5/data-availability/verify",
                post(http_verify_data_availability_v1),
            )
            .route(
                "/v5/aggregates/execute",
                post(http_execute_aggregate_v1),
            )
            .route(
                "/v5/aggregates/prove",
                post(http_prove_aggregate_v1),
            )
            .route(
                "/v5/aggregates/verify",
                post(http_verify_aggregate_v1),
            )
            .route("/v5/receipts/wrap", post(http_wrap_groth16_v5))
            .route(
                "/v5/receipts/identity-p254",
                post(http_wrap_identity_p254_v5),
            )
            .route("/v5/receipts/groth16", post(http_wrap_groth16_from_p254_v5))
            .layer(axum::extract::DefaultBodyLimit::max(MAX_HTTP_BODY_BYTES_V5))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind(&address)
            .await
            .with_context(|| format!("bind {address}"))?;
        eprintln!("Decision: zkdeal CUDA prover is listening on {address}");
        axum::serve(listener, app)
            .await
            .context("serve CUDA prover")
    })
}

#[cfg(test)]
mod http_auth_tests {
    use super::*;

    fn bearer(value: &str) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_str(value).unwrap(),
        );
        headers
    }

    #[test]
    fn v5_routes_require_the_configured_shared_secret() {
        let empty = axum::http::HeaderMap::new();
        assert!(authorized_v5(None, &empty));
        assert!(!authorized_v5(Some("s3cret"), &empty));
        assert!(!authorized_v5(Some("s3cret"), &bearer("s3cret")));
        assert!(!authorized_v5(Some("s3cret"), &bearer("Bearer s3cre")));
        assert!(!authorized_v5(Some("s3cret"), &bearer("Bearer s3crets")));
        assert!(!authorized_v5(Some("s3cret"), &bearer("Bearer S3CRET")));
        assert!(authorized_v5(Some("s3cret"), &bearer("Bearer s3cret")));
    }
}

#[cfg(test)]
mod http_metrics_tests {
    use super::*;

    fn state_with_token(token: Option<&str>) -> HttpStateV5 {
        HttpStateV5 {
            gpu_gate: Arc::new(tokio::sync::Semaphore::new(1)),
            token: token.map(|value| Arc::new(value.to_owned())),
            metrics: Arc::new(HttpMetricsV5::new()),
        }
    }

    fn ok_command(_raw: &str) -> Result<serde_json::Value> {
        Ok(serde_json::json!({ "ok": true }))
    }

    #[tokio::test]
    async fn requests_are_counted_per_route_and_outcome() {
        let guarded = state_with_token(Some("s3cret"));
        let unauthorized = http_command_v5(
            guarded.clone(),
            "/v5/rooms/prove",
            axum::http::HeaderMap::new(),
            axum::body::Bytes::new(),
            ok_command,
            false,
        )
        .await;
        assert_eq!(unauthorized.status(), axum::http::StatusCode::UNAUTHORIZED);
        let text = render_metrics_v5(&guarded.metrics, None);
        assert!(text.contains(
            "zkdeal_prover_requests_total{route=\"/v5/rooms/prove\",outcome=\"unauthorized\"} 1"
        ));

        let open = state_with_token(None);
        let accepted = http_command_v5(
            open.clone(),
            "/v5/rooms/verify",
            axum::http::HeaderMap::new(),
            axum::body::Bytes::from_static(b"{}"),
            ok_command,
            false,
        )
        .await;
        assert_eq!(accepted.status(), axum::http::StatusCode::OK);
        let text = render_metrics_v5(&open.metrics, None);
        assert!(text
            .contains("zkdeal_prover_requests_total{route=\"/v5/rooms/verify\",outcome=\"ok\"} 1"));
    }

    #[test]
    fn metrics_render_type_lines_and_gpu_gauges() {
        let metrics = HttpMetricsV5::new();
        metrics.record("/v5/rooms/prove", "rejected");
        metrics.record("/v5/rooms/prove", "rejected");
        let text = render_metrics_v5(&metrics, Some((97.0, 10240.0, 312.5)));
        assert!(text.contains("# TYPE zkdeal_prover_uptime_seconds gauge"));
        assert!(text.contains("# TYPE zkdeal_prover_requests_total counter"));
        assert!(text.contains(
            "zkdeal_prover_requests_total{route=\"/v5/rooms/prove\",outcome=\"rejected\"} 2"
        ));
        assert!(text.contains("# TYPE zkdeal_prover_gpu_utilization_percent gauge"));
        assert!(text.contains("zkdeal_prover_gpu_utilization_percent 97\n"));
        assert!(text.contains("# TYPE zkdeal_prover_gpu_memory_used_mib gauge"));
        assert!(text.contains("zkdeal_prover_gpu_memory_used_mib 10240\n"));
        assert!(text.contains("# TYPE zkdeal_prover_gpu_power_watts gauge"));
        assert!(text.contains("zkdeal_prover_gpu_power_watts 312.5\n"));
    }

    #[test]
    fn metrics_omit_gpu_gauges_without_a_driver_sample() {
        let metrics = HttpMetricsV5::new();
        let text = render_metrics_v5(&metrics, None);
        assert!(text.contains("zkdeal_prover_uptime_seconds "));
        assert!(!text.contains("zkdeal_prover_gpu_"));
    }
}
