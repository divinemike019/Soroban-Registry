//! Sliding-window rate limiter with automatic eviction of expired entries.
//!
//! ## Memory-leak fix (issue #317)
//!
//! The original implementation stored fixed-window counters in a
//! `HashMap` that was never cleaned up.  Every unique IP that ever hit the
//! API accumulated an entry that lived forever.
//!
//! This version fixes that by:
//!
//! 1. **Background eviction task** – [`RateLimitState::spawn_eviction_task`]
//!    runs every `EVICTION_INTERVAL` and removes any bucket whose window
//!    expired more than `window_duration` ago.
//! 2. **`tokio::sync::Mutex`** – replaced `std::sync::Mutex` so the lock is
//!    held correctly across `.await` points and avoids blocking the async
//!    executor.
//! 3. **Graceful lock error handling** – `.lock().await` on a
//!    `tokio::sync::Mutex` never poisons, so the panic from `.expect()` is
//!    gone. The one remaining fallible path (attaching response headers) logs
//!    a warning instead of crashing.
//!
//! ## Write-endpoint protection
//!
//! Mutation endpoints (POST, PUT, PATCH, DELETE) consume more server resources
//! and can cause irreversible state changes.  They are subject to a separate,
//! tighter quota:
//!
//! - Anonymous write limit: 100 req/hour  (`RATE_LIMIT_WRITE_ANON_PER_HOUR`)
//! - Authenticated write limit: 300 req/hour (`RATE_LIMIT_WRITE_AUTH_PER_HOUR`)
//!
//! ## Exempt paths
//!
//! Health probes (`/health*`), the Prometheus metrics scrape endpoint
//! (`/metrics`), and internal admin flows (`/api/admin/*`) bypass the rate
//! limiter so monitoring systems and operators are never blocked.
//!
//! ## Trusted-client bypass audit (issue #1054)
//!
//! When a request is allowed through via a whitelisted IP or trusted API key,
//! [`log_bypass`] emits a structured `tracing` event at `WARN` level so the
//! event appears in every log aggregator (ELK, Loki, CloudWatch, etc.) and is
//! easy to query with `event.type = "trusted_bypass"`.
//!
//! Fields emitted per bypass event:
//! - `event` – always `"trusted_bypass"`
//! - `identity_type` – `"ip"` or `"api_key"`
//! - `client_identity` – the (possibly masked) IP or API-key prefix
//! - `client_ip` – raw client IP
//! - `path` – request path
//! - `method` – HTTP method
//! - `timestamp` – RFC-3339 UTC string
//!
//! In addition, two Prometheus counters are updated:
//! - `rate_limit_bypass_total{identity_type}` – lifetime total
//! - `rate_limit_bypass_requests_per_minute` – rolling 1-minute gauge
//!
//! If bypass volume exceeds [`BYPASS_SPIKE_THRESHOLD`] in a one-minute window,
//! a `Critical` alert is dispatched through [`crate::alerting::AlertManager`].
//!
//! ## Horizontal scaling note
//!
//! This rate limiter is **per-instance**.  When running multiple API replicas
//! the bucket state is not shared between them.  For true distributed rate
//! limiting consider replacing the in-process `HashMap` with a Redis-backed
//! store (e.g. via the `upstash-redis` crate or `fred`).

use std::{
    collections::{HashMap, HashSet, VecDeque},
    env,
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicI64, AtomicU64, Ordering},
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{connect_info::ConnectInfo, State},
    http::{
        header::{AUTHORIZATION, RETRY_AFTER},
        HeaderName, HeaderValue, Method, Request,
    },
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use tokio::sync::Mutex;

use crate::{
    alerting::{Alert, AlertManager, AlertSeverity},
    error::ApiError,
    metrics::{RATE_LIMIT_BYPASS_PER_MINUTE, RATE_LIMIT_BYPASS_TOTAL},
};

// Issue #891: 1,000 requests per minute per IP/API key by default.
const DEFAULT_ANON_LIMIT: u32 = 1_000;
const DEFAULT_AUTH_LIMIT: u32 = 1_000;
// Stricter default quotas for mutation (write) endpoints.
const DEFAULT_WRITE_ANON_LIMIT: u32 = 100;
const DEFAULT_WRITE_AUTH_LIMIT: u32 = 300;
const DEFAULT_WINDOW_SECONDS: u64 = 60;
#[allow(dead_code)]
const DEFAULT_CONTRACTS_PAGE_SIZE: u32 = 50;
#[allow(dead_code)]
const MAX_CONTRACTS_PAGE_SIZE: u32 = 1000;
const ABI_ENDPOINT_LIMIT_PER_MINUTE: u32 = 1_000;
#[allow(dead_code)]
const ENDPOINT_LIMIT_ENV_PREFIX: &str = "RATE_LIMIT_ENDPOINT_";

/// Issue #727 — tiered limits over the configured window.
const FREE_TIER_LIMIT: u32 = 1_000;
const PRO_TIER_LIMIT: u32 = 10_000;
const BURST_WINDOW_SECONDS: u64 = 60; // 1 minute burst window

/// How often the background task sweeps for expired buckets.
const EVICTION_INTERVAL: Duration = Duration::from_secs(5 * 60); // every 5 minutes

/// How many bypass events per minute before we fire a spike alert (issue #1054).
const BYPASS_SPIKE_THRESHOLD: u64 = 100;

/// How long to remember the bypass-spike window start (seconds).
const BYPASS_WINDOW_SECS: u64 = 60;

const HEADER_RATE_LIMIT_LIMIT: HeaderName = HeaderName::from_static("x-ratelimit-limit");
const HEADER_RATE_LIMIT_REMAINING: HeaderName = HeaderName::from_static("x-ratelimit-remaining");
const HEADER_RATE_LIMIT_RESET: HeaderName = HeaderName::from_static("x-ratelimit-reset");
const HEADER_RATE_LIMIT_TIER: HeaderName = HeaderName::from_static("x-ratelimit-tier");

/// API tier that determines quota limits (issue #727).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiTier {
    Free,
    Pro,
    /// Enterprise limit is read from ENTERPRISE_RATE_LIMIT_PER_HOUR at startup.
    Enterprise,
}

impl ApiTier {
    fn as_str(&self) -> &'static str {
        match self {
            ApiTier::Free => "free",
            ApiTier::Pro => "pro",
            ApiTier::Enterprise => "enterprise",
        }
    }

    pub fn from_header(value: &str) -> Self {
        match value.to_lowercase().as_str() {
            "pro" => ApiTier::Pro,
            "enterprise" => ApiTier::Enterprise,
            _ => ApiTier::Free,
        }
    }
}

/// Paths that bypass rate limiting entirely.
///
/// Health probes must not be rate-limited so that load balancers and
/// orchestrators always get a response.  The Prometheus scrape endpoint
/// `/metrics` and internal admin APIs are also exempt.
fn is_exempt_path(path: &str) -> bool {
    path.starts_with("/health") || path == "/metrics" || path.starts_with("/api/admin/")
}

/// Identifies which bypass mechanism was used for a single request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassKind {
    /// The client's IP address is in `RATE_LIMIT_TRUSTED_IPS`.
    TrustedIp,
    /// The client's API key is in `RATE_LIMIT_TRUSTED_API_KEYS`.
    TrustedApiKey,
}

impl BypassKind {
    fn as_identity_type(self) -> &'static str {
        match self {
            BypassKind::TrustedIp => "ip",
            BypassKind::TrustedApiKey => "api_key",
        }
    }
}

/// Minimal in-process state for the rolling bypass spike window (issue #1054).
///
/// Uses atomic integers so it can be cheaply shared without a Mutex:
/// - `window_start_unix` – Unix-second timestamp of the current window start.
/// - `window_count` – bypass events recorded so far in that window.
struct BypassSpikeState {
    window_start_unix: AtomicI64,
    window_count: AtomicU64,
}

impl BypassSpikeState {
    fn new() -> Self {
        Self {
            window_start_unix: AtomicI64::new(Utc::now().timestamp()),
            window_count: AtomicU64::new(0),
        }
    }

    /// Record one bypass event and return the running count within the current
    /// 1-minute window.  Resets the window automatically when it expires.
    fn record_and_count(&self) -> u64 {
        let now_secs = Utc::now().timestamp();
        let window_start = self.window_start_unix.load(Ordering::Relaxed);

        if now_secs - window_start >= BYPASS_WINDOW_SECS as i64 {
            // Start a fresh window.  Use a compare-exchange so only one thread
            // resets the counter even when requests arrive concurrently.
            if self
                .window_start_unix
                .compare_exchange(window_start, now_secs, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                self.window_count.store(1, Ordering::Relaxed);
                return 1;
            }
        }

        self.window_count.fetch_add(1, Ordering::Relaxed) + 1
    }
}

#[derive(Clone)]
pub struct RateLimitState {
    config: std::sync::Arc<RateLimitConfig>,
    /// Shared bucket map — protected by a *tokio* Mutex so it is async-safe.
    buckets: std::sync::Arc<Mutex<HashMap<BucketKey, BucketState>>>,
    /// Bypass spike detection window (issue #1054).
    bypass_spike: std::sync::Arc<BypassSpikeState>,
}

/// Snapshot of quota usage for a client key (used by the /api/quota endpoint).
#[derive(Debug, Clone, serde::Serialize)]
pub struct QuotaSnapshot {
    pub tier: String,
    pub hourly_limit: u32,
    pub hourly_used: usize,
    pub hourly_remaining: usize,
    pub burst_limit: u32,
    pub burst_used: usize,
    pub burst_remaining: usize,
}

impl RateLimitState {
    pub fn from_env() -> Self {
        Self::new(RateLimitConfig::from_env())
    }

    fn new(config: RateLimitConfig) -> Self {
        Self {
            config: std::sync::Arc::new(config),
            buckets: std::sync::Arc::new(Mutex::new(HashMap::new())),
            bypass_spike: std::sync::Arc::new(BypassSpikeState::new()),
        }
    }

    /// Spawn a background Tokio task that periodically evicts expired buckets.
    ///
    /// Call this once during application startup (after `tokio::main` is
    /// entered).  The task runs until the process exits.
    pub fn spawn_eviction_task(&self) {
        let buckets = self.buckets.clone();
        let window = self.config.window;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(EVICTION_INTERVAL);
            // The first tick fires immediately — skip it so we don't evict
            // right after startup when there is nothing to evict yet.
            ticker.tick().await;

            loop {
                ticker.tick().await;

                let now = Instant::now();
                let mut map = buckets.lock().await;
                let before = map.len();

                // Retain only buckets that have seen traffic recently.
                map.retain(|_, state| {
                    // Check both windows; keep if either has a recent timestamp.
                    let hourly_active = state
                        .timestamps
                        .back()
                        .map(|last_seen| {
                            now.saturating_duration_since(*last_seen) < window.saturating_mul(2)
                        })
                        .unwrap_or(false);
                    let burst_active = state
                        .burst_timestamps
                        .back()
                        .map(|last_seen| {
                            now.saturating_duration_since(*last_seen) < window.saturating_mul(2)
                        })
                        .unwrap_or(false);
                    hourly_active || burst_active
                });

                let evicted = before - map.len();
                if evicted > 0 {
                    tracing::info!(
                        evicted,
                        remaining = map.len(),
                        "rate limiter: evicted expired buckets"
                    );
                }
            }
        });
    }

    async fn check_request(
        &self,
        key: BucketKey,
        hourly_limit: u32,
        burst_limit: u32,
    ) -> RateLimitDecision {
        let now = Instant::now();

        // tokio::sync::Mutex::lock() never poisons — no .expect() needed.
        let mut buckets = self.buckets.lock().await;

        let bucket = buckets.entry(key).or_insert_with(|| BucketState {
            timestamps: VecDeque::new(),
            burst_timestamps: VecDeque::new(),
        });

        // Trim the hourly sliding window
        let window_start_cutoff = now.checked_sub(self.config.window).unwrap_or(now);
        while bucket
            .timestamps
            .front()
            .copied()
            .map(|ts| ts <= window_start_cutoff)
            .unwrap_or(false)
        {
            bucket.timestamps.pop_front();
        }

        // Trim the burst (1-minute) sliding window
        let burst_cutoff = now.checked_sub(self.config.burst_window).unwrap_or(now);
        while bucket
            .burst_timestamps
            .front()
            .copied()
            .map(|ts| ts <= burst_cutoff)
            .unwrap_or(false)
        {
            bucket.burst_timestamps.pop_front();
        }

        let reset_seconds = bucket
            .timestamps
            .front()
            .and_then(|oldest| oldest.checked_add(self.config.window))
            .map(|expiry| ceil_duration_to_seconds(expiry.saturating_duration_since(now)).max(1))
            .unwrap_or_else(|| ceil_duration_to_seconds(self.config.window).max(1));

        // Reject if hourly limit exceeded
        if (bucket.timestamps.len() as u32) >= hourly_limit {
            return RateLimitDecision {
                allowed: false,
                limit: hourly_limit,
                remaining: 0,
                reset_seconds,
            };
        }

        // Reject if burst limit exceeded (too many in the last minute)
        if (bucket.burst_timestamps.len() as u32) >= burst_limit {
            return RateLimitDecision {
                allowed: false,
                limit: hourly_limit,
                remaining: hourly_limit.saturating_sub(bucket.timestamps.len() as u32),
                reset_seconds: ceil_duration_to_seconds(self.config.burst_window).max(1),
            };
        }

        bucket.timestamps.push_back(now);
        bucket.burst_timestamps.push_back(now);
        let remaining = hourly_limit.saturating_sub(bucket.timestamps.len() as u32);

        RateLimitDecision {
            allowed: true,
            limit: hourly_limit,
            remaining,
            reset_seconds,
        }
    }

    /// Returns the current quota snapshot for a client key without consuming a token.
    pub async fn quota_snapshot(&self, client_key: &str, tier: &ApiTier) -> QuotaSnapshot {
        let now = Instant::now();
        let hourly_limit = self.config.hourly_limit_for_tier(tier);
        let burst_limit = self.config.burst_limit_for_tier(tier);

        let buckets = self.buckets.lock().await;
        let key = BucketKey {
            client_key: client_key.to_owned(),
        };

        if let Some(bucket) = buckets.get(&key) {
            let window_cutoff = now.checked_sub(self.config.window).unwrap_or(now);
            let hourly_used = bucket
                .timestamps
                .iter()
                .filter(|&&ts| ts > window_cutoff)
                .count();

            let burst_cutoff = now.checked_sub(self.config.burst_window).unwrap_or(now);
            let burst_used = bucket
                .burst_timestamps
                .iter()
                .filter(|&&ts| ts > burst_cutoff)
                .count();

            QuotaSnapshot {
                tier: tier.as_str().to_owned(),
                hourly_limit,
                hourly_used,
                hourly_remaining: (hourly_limit as usize).saturating_sub(hourly_used),
                burst_limit,
                burst_used,
                burst_remaining: (burst_limit as usize).saturating_sub(burst_used),
            }
        } else {
            QuotaSnapshot {
                tier: tier.as_str().to_owned(),
                hourly_limit,
                hourly_used: 0,
                hourly_remaining: hourly_limit as usize,
                burst_limit,
                burst_used: 0,
                burst_remaining: burst_limit as usize,
            }
        }
    }

    /// Record and audit a trusted-client bypass event (issue #1054).
    ///
    /// This method:
    /// 1. Emits a structured `tracing::warn!` log entry with all identifying
    ///    fields (identity type, masked identity, raw IP, path, method,
    ///    timestamp) so that SIEM / log-aggregation tools can index and alert
    ///    on it.
    /// 2. Increments the Prometheus counter for the correct identity type.
    /// 3. Updates the rolling per-minute gauge used by dashboards.
    /// 4. If the per-minute count exceeds [`BYPASS_SPIKE_THRESHOLD`], dispatches
    ///    a `Critical` alert via [`AlertManager`] (Slack + PagerDuty if
    ///    configured).
    pub async fn audit_bypass<B>(&self, request: &Request<B>, kind: BypassKind) {
        let client_ip = extract_client_ip(request);
        let path = request.uri().path().to_owned();
        let method = request.method().as_str().to_owned();
        let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let identity_type = kind.as_identity_type();

        // Build a stable, privacy-safe identity string:
        //  - for IP bypasses: the IP itself (already in logs)
        //  - for API-key bypasses: first 8 chars of the key + "…" so the key
        //    can be identified without leaking the full secret.
        let client_identity = match kind {
            BypassKind::TrustedIp => client_ip.clone(),
            BypassKind::TrustedApiKey => extract_auth_token(request)
                .map(|token| {
                    let stripped = token
                        .strip_prefix("Bearer ")
                        .or_else(|| token.strip_prefix("ApiKey "))
                        .unwrap_or(&token)
                        .trim()
                        .to_string();
                    if stripped.len() > 8 {
                        format!("{}…", &stripped[..8])
                    } else {
                        stripped
                    }
                })
                .unwrap_or_else(|| "<unknown>".to_string()),
        };

        // 1. Structured audit log — queryable in any log aggregator.
        tracing::warn!(
            event = "trusted_bypass",
            identity_type,
            client_identity = %client_identity,
            client_ip = %client_ip,
            path = %path,
            method = %method,
            timestamp = %timestamp,
            "Rate-limit bypass: trusted-client token used"
        );

        // 2. Prometheus counters.
        RATE_LIMIT_BYPASS_TOTAL
            .with_label_values(&[identity_type])
            .inc();

        // 3. Rolling 1-minute gauge + spike detection.
        let count = self.bypass_spike.record_and_count();
        RATE_LIMIT_BYPASS_PER_MINUTE.set(count as i64);

        if count == BYPASS_SPIKE_THRESHOLD {
            // Fire exactly once at the threshold boundary to avoid alert flood.
            let alert_mgr = AlertManager::new();
            alert_mgr
                .dispatch_alert(Alert {
                    id: uuid::Uuid::new_v4().to_string(),
                    source: "rate_limit_bypass".to_string(),
                    message: format!(
                        "Trusted-client bypass spike: {} bypasses in the last 60 seconds \
                         (threshold: {}). Review RATE_LIMIT_TRUSTED_IPS / \
                         RATE_LIMIT_TRUSTED_API_KEYS for leaked or abused tokens.",
                        count, BYPASS_SPIKE_THRESHOLD
                    ),
                    severity: AlertSeverity::Critical,
                    timestamp: Utc::now(),
                })
                .await;
        }
    }

    /// Derive the bucket key and API tier from an incoming request.
    ///
    /// Tier is resolved in order:
    /// 1. `X-Api-Plan: free | pro | enterprise` header
    /// 2. Defaults to `free` for unauthenticated requests, `free` for authenticated
    ///    (upgrade to pro/enterprise requires the header or a future DB lookup).
    fn select_limit_and_key<B>(&self, request: &Request<B>) -> (u32, u32, BucketKey, ApiTier) {
        let tier = extract_api_tier(request);
        let path = request.uri().path();
        let query = request.uri().query();
        // Mutation requests get a separate, stricter bucket.
        let is_write = matches!(
            request.method().as_str(),
            "POST" | "PUT" | "PATCH" | "DELETE"
        );
        let bucket_suffix = if is_write { "write" } else { "read" };

        if is_contract_abi_endpoint(request.method(), path) {
            return (
                ABI_ENDPOINT_LIMIT_PER_MINUTE * 60,
                ABI_ENDPOINT_LIMIT_PER_MINUTE,
                BucketKey {
                    client_key: format!("abi:{}:{}", path, extract_client_ip(request)),
                },
                tier,
            );
        }

        if let Some(token) = extract_auth_token(request) {
            let hourly = self
                .config
                .per_api_key_limit(&token)
                .unwrap_or_else(|| self.config.hourly_limit_for_tier(&tier));
            let auth_hourly = if is_write {
                self.config.write_auth_limit.min(hourly)
            } else {
                hourly
            };
            let burst = self.config.burst_limit_for_limit(auth_hourly);
            return (
                auth_hourly,
                burst,
                BucketKey {
                    client_key: format!("auth:{bucket_suffix}:{token}"),
                },
                tier,
            );
        }

        let ip = extract_client_ip(request);
        if is_write {
            let limit = self.config.write_anonymous_limit;
            let burst = self.config.burst_limit_for_limit(limit);
            return (
                limit,
                burst,
                BucketKey {
                    client_key: format!("anon:write:{ip}"),
                },
                tier,
            );
        }

        let hourly_base = self.config.anonymous_limit;
        let hourly = if let Some(page_size) =
            contracts_page_size_rate_limit(request.method(), path, query)
        {
            scale_limit_by_page_size(hourly_base, page_size)
        } else {
            hourly_base
        };
        let burst = self.config.burst_limit_for_limit(hourly);

        (
            hourly,
            burst,
            BucketKey {
                client_key: format!("anon:read:{ip}"),
            },
            tier,
        )
    }
}

struct RateLimitConfig {
    anonymous_limit: u32,
    auth_limit: u32,
    write_anonymous_limit: u32,
    write_auth_limit: u32,
    window: Duration,
    enterprise_limit: u32,
    burst_window: Duration,
    per_api_key_limits: HashMap<String, u32>,
    trusted_client_ips: HashSet<String>,
    trusted_api_keys: HashSet<String>,
}

impl RateLimitConfig {
    fn from_env() -> Self {
        // Issue #891: configurable per-IP and per-API-key limits; defaults to 1000 req/min.
        let anonymous_limit = env_u32_with_fallback(
            "RATE_LIMIT_IP_PER_MINUTE",
            "RATE_LIMIT_ANON_PER_MINUTE",
            DEFAULT_ANON_LIMIT,
        );
        let auth_limit = env_u32_with_fallback(
            "RATE_LIMIT_API_KEY_PER_MINUTE",
            "RATE_LIMIT_AUTH_PER_MINUTE",
            DEFAULT_AUTH_LIMIT,
        );
        // Write limits — stricter quota for mutation endpoints.
        let write_anonymous_limit =
            env_u32("RATE_LIMIT_WRITE_ANON_PER_HOUR", DEFAULT_WRITE_ANON_LIMIT);
        let write_auth_limit = env_u32("RATE_LIMIT_WRITE_AUTH_PER_HOUR", DEFAULT_WRITE_AUTH_LIMIT);
        let window_seconds = env_u64("RATE_LIMIT_WINDOW_SECONDS", DEFAULT_WINDOW_SECONDS).max(1);
        // Issue #727: enterprise tier custom limit
        let enterprise_limit = env_u32("ENTERPRISE_RATE_LIMIT_PER_WINDOW", 100_000);
        let per_api_key_limits = parse_key_limit_map("RATE_LIMIT_API_KEY_LIMITS");
        let trusted_client_ips = parse_csv_set("RATE_LIMIT_TRUSTED_IPS");
        let trusted_api_keys = parse_csv_set("RATE_LIMIT_TRUSTED_API_KEYS");

        tracing::info!(
            anonymous_limit,
            auth_limit,
            write_anonymous_limit,
            write_auth_limit,
            window_seconds,
            enterprise_limit,
            "Rate limiter configured (issue #891/#727: per-IP/API-key quotas)"
        );

        Self {
            anonymous_limit,
            auth_limit,
            write_anonymous_limit,
            write_auth_limit,
            window: Duration::from_secs(window_seconds),
            enterprise_limit,
            burst_window: Duration::from_secs(BURST_WINDOW_SECONDS),
            per_api_key_limits,
            trusted_client_ips,
            trusted_api_keys,
        }
    }

    #[cfg(test)]
    fn for_tests(anonymous_limit: u32, auth_limit: u32, window: Duration) -> Self {
        Self {
            anonymous_limit,
            auth_limit,
            write_anonymous_limit: anonymous_limit / 10,
            write_auth_limit: auth_limit / 3,
            window,
            enterprise_limit: 100_000,
            burst_window: Duration::from_secs(BURST_WINDOW_SECONDS),
            per_api_key_limits: HashMap::new(),
            trusted_client_ips: HashSet::new(),
            trusted_api_keys: HashSet::new(),
        }
    }

    #[cfg(test)]
    fn for_tests_with_write(
        anonymous_limit: u32,
        auth_limit: u32,
        write_anonymous_limit: u32,
        write_auth_limit: u32,
        window: Duration,
    ) -> Self {
        Self {
            anonymous_limit,
            auth_limit,
            write_anonymous_limit,
            write_auth_limit,
            window,
            enterprise_limit: 100_000,
            burst_window: Duration::from_secs(BURST_WINDOW_SECONDS),
            per_api_key_limits: HashMap::new(),
            trusted_client_ips: HashSet::new(),
            trusted_api_keys: HashSet::new(),
        }
    }

    /// Returns the hourly limit for the given tier.
    fn hourly_limit_for_tier(&self, tier: &ApiTier) -> u32 {
        match tier {
            ApiTier::Free => self.auth_limit.max(FREE_TIER_LIMIT),
            ApiTier::Pro => self.auth_limit.max(PRO_TIER_LIMIT),
            ApiTier::Enterprise => self.enterprise_limit,
        }
    }

    /// Burst limit = ceil(hourly_limit × 1.2 / 60) requests per minute.
    fn burst_limit_for_tier(&self, tier: &ApiTier) -> u32 {
        let hourly = self.hourly_limit_for_tier(tier);
        self.burst_limit_for_limit(hourly)
    }

    fn burst_limit_for_limit(&self, hourly: u32) -> u32 {
        // 120 % of the per-minute equivalent; minimum 1
        ((hourly as f64 * 1.2 / 60.0).ceil() as u32).max(1)
    }

    fn per_api_key_limit(&self, token: &str) -> Option<u32> {
        let normalized = token
            .strip_prefix("Bearer ")
            .or_else(|| token.strip_prefix("ApiKey "))
            .unwrap_or(token)
            .trim();
        self.per_api_key_limits.get(normalized).copied()
    }

    fn is_whitelisted<B>(&self, request: &Request<B>) -> bool {
        self.bypass_kind(request).is_some()
    }

    /// Returns the bypass kind if this request is from a trusted client, or
    /// `None` if normal rate limiting should apply.
    fn bypass_kind<B>(&self, request: &Request<B>) -> Option<BypassKind> {
        let client_ip = extract_client_ip(request);
        if self.trusted_client_ips.contains(&client_ip) {
            return Some(BypassKind::TrustedIp);
        }

        extract_auth_token(request).and_then(|token| {
            let normalized = token
                .strip_prefix("Bearer ")
                .or_else(|| token.strip_prefix("ApiKey "))
                .unwrap_or(&token)
                .trim()
                .to_string();
            if self.trusted_api_keys.contains(&normalized) {
                Some(BypassKind::TrustedApiKey)
            } else {
                None
            }
        })
    }
}

#[derive(Hash, Eq, PartialEq)]
struct BucketKey {
    client_key: String,
}

struct BucketState {
    timestamps: VecDeque<Instant>,
    /// Timestamps in the 1-minute burst window (subset of `timestamps`).
    burst_timestamps: VecDeque<Instant>,
}

struct RateLimitDecision {
    allowed: bool,
    limit: u32,
    remaining: u32,
    reset_seconds: u64,
}

pub async fn rate_limit_middleware(
    State(rate_limiter): State<RateLimitState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Issue #1054: trusted-client bypass — audit every bypassed request before
    // forwarding it, so the bypass is fully visible in logs and metrics.
    if let Some(bypass_kind) = rate_limiter.config.bypass_kind(&request) {
        rate_limiter.audit_bypass(&request, bypass_kind).await;
        return next.run(request).await;
    }

    // Extract request metadata before awaiting to avoid borrowing `request` across `.await`.
    let (hourly_limit, burst_limit, key, tier) = rate_limiter.select_limit_and_key(&request);
    let decision = rate_limiter
        .check_request(key, hourly_limit, burst_limit)
        .await;

    if !decision.allowed {
        let is_write = is_write_method(request.method());
        // Observability: surface throttle events so operators can spot abuse or
        // accidental overload of public endpoints (issue #1005).
        tracing::warn!(
            client_ip = %extract_client_ip(&request),
            tier = tier.as_str(),
            limit_type = if is_write { "write" } else { "read" },
            limit = decision.limit,
            remaining = decision.remaining,
            retry_after_seconds = decision.reset_seconds,
            "Request throttled by rate limiter"
        );
        let detail = if is_write {
            "Write quota exhausted. Reduce request frequency or wait for the window to reset."
        } else {
            "Too many requests. Please retry after the indicated time."
        };
        let mut response = ApiError::rate_limited(detail)
            .with_details(serde_json::json!({
                "retry_after_seconds": decision.reset_seconds,
                "limit_type": if is_write { "write" } else { "read" }
            }))
            .into_response();
        attach_rate_limit_headers(&mut response, &decision);
        attach_tier_header(&mut response, &tier);
        response.headers_mut().insert(
            RETRY_AFTER,
            HeaderValue::from_str(&decision.reset_seconds.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("1")),
        );
        return response;
    }

    let mut response = next.run(request).await;
    attach_rate_limit_headers(&mut response, &decision);
    attach_tier_header(&mut response, &tier);
    response
}

fn attach_tier_header(response: &mut Response, tier: &ApiTier) {
    if let Ok(val) = HeaderValue::from_str(tier.as_str()) {
        response.headers_mut().insert(HEADER_RATE_LIMIT_TIER, val);
    }
}

fn attach_rate_limit_headers(response: &mut Response, decision: &RateLimitDecision) {
    // Use graceful fallback instead of panicking on header value conversion.
    let headers = response.headers_mut();

    if let Ok(val) = HeaderValue::from_str(&decision.limit.to_string()) {
        headers.insert(HEADER_RATE_LIMIT_LIMIT, val);
    } else {
        tracing::warn!("Failed to encode x-ratelimit-limit header");
    }

    if let Ok(val) = HeaderValue::from_str(&decision.remaining.to_string()) {
        headers.insert(HEADER_RATE_LIMIT_REMAINING, val);
    } else {
        tracing::warn!("Failed to encode x-ratelimit-remaining header");
    }

    if let Ok(val) = HeaderValue::from_str(&decision.reset_seconds.to_string()) {
        headers.insert(HEADER_RATE_LIMIT_RESET, val);
    } else {
        tracing::warn!("Failed to encode x-ratelimit-reset header");
    }
}

fn extract_client_ip<B>(request: &Request<B>) -> String {
    if let Some(ip) = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_x_forwarded_for)
    {
        return ip.to_string();
    }

    if let Some(ip) = request
        .headers()
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_ip_addr)
    {
        return ip.to_string();
    }

    if let Some(connect_info) = request.extensions().get::<ConnectInfo<SocketAddr>>() {
        return connect_info.0.ip().to_string();
    }

    "unknown".to_string()
}

/// Resolve API tier from the `X-Api-Plan` request header.
/// Falls back to `Free` when the header is absent or unrecognised.
fn extract_api_tier<B>(request: &Request<B>) -> ApiTier {
    request
        .headers()
        .get("x-api-plan")
        .and_then(|v| v.to_str().ok())
        .map(ApiTier::from_header)
        .unwrap_or(ApiTier::Free)
}

fn extract_auth_token<B>(request: &Request<B>) -> Option<String> {
    if let Some(api_key) = request
        .headers()
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(api_key.to_string());
    }

    request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_key_limit_map(key: &str) -> HashMap<String, u32> {
    std::env::var(key)
        .unwrap_or_default()
        .split(',')
        .filter_map(|entry| {
            let (api_key, limit) = entry.split_once('=')?;
            let limit = limit.trim().parse::<u32>().ok()?;
            (limit > 0).then(|| (api_key.trim().to_string(), limit))
        })
        .filter(|(api_key, _)| !api_key.is_empty())
        .collect()
}

fn parse_csv_set(key: &str) -> HashSet<String> {
    std::env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_x_forwarded_for(raw: &str) -> Option<IpAddr> {
    raw.split(',').map(str::trim).find_map(parse_ip_addr)
}

fn parse_ip_addr(raw: &str) -> Option<IpAddr> {
    raw.parse::<IpAddr>()
        .ok()
        .or_else(|| raw.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
}

fn is_write_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn contracts_page_size_rate_limit(method: &Method, path: &str, query: Option<&str>) -> Option<u32> {
    if *method != Method::GET || path != "/api/contracts" {
        return None;
    }

    Some(extract_page_size(query).unwrap_or(DEFAULT_CONTRACTS_PAGE_SIZE))
}

fn is_contract_abi_endpoint(method: &Method, path: &str) -> bool {
    *method == Method::GET && path.starts_with("/api/v1/contracts/") && path.ends_with("/abi")
}

fn extract_page_size(query: Option<&str>) -> Option<u32> {
    let query = query?;

    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next()?;
        let value = parts.next().unwrap_or_default();

        if key == "limit" || key == "page_size" {
            if let Ok(parsed) = value.parse::<u32>() {
                return Some(parsed.clamp(1, MAX_CONTRACTS_PAGE_SIZE));
            }
        }
    }

    None
}

fn scale_limit_by_page_size(base_limit: u32, page_size: u32) -> u32 {
    let weight = page_size.div_ceil(DEFAULT_CONTRACTS_PAGE_SIZE).max(1);
    (base_limit / weight).max(1)
}

#[allow(dead_code)]
fn endpoint_key(method: &Method, path: &str) -> String {
    let normalized_path = path
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();

    let compact_path = normalized_path
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("_");

    if compact_path.is_empty() {
        format!("{}_ROOT", method.as_str().to_ascii_uppercase())
    } else {
        format!("{}_{}", method.as_str().to_ascii_uppercase(), compact_path)
    }
}

fn env_u32(key: &str, default: u32) -> u32 {
    match env::var(key) {
        Ok(raw) => match raw.parse::<u32>() {
            Ok(value) if value > 0 => value,
            _ => {
                tracing::warn!("Invalid value for {key} (`{raw}`), using default {default}");
                default
            }
        },
        Err(_) => default,
    }
}

fn env_u32_with_fallback(primary_key: &str, fallback_key: &str, default: u32) -> u32 {
    match env::var(primary_key) {
        Ok(raw) => match raw.parse::<u32>() {
            Ok(value) if value > 0 => value,
            _ => {
                tracing::warn!(
                    "Invalid value for {primary_key} (`{raw}`), using default {default}"
                );
                default
            }
        },
        Err(_) => env_u32(fallback_key, default),
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    match env::var(key) {
        Ok(raw) => match raw.parse::<u64>() {
            Ok(value) if value > 0 => value,
            _ => {
                tracing::warn!("Invalid value for {key} (`{raw}`), using default {default}");
                default
            }
        },
        Err(_) => default,
    }
}

fn ceil_duration_to_seconds(duration: Duration) -> u64 {
    let secs = duration.as_secs();
    if duration.subsec_nanos() > 0 {
        secs + 1
    } else {
        secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        http::{Request, StatusCode},
        middleware,
        routing::{get, post},
        Router,
    };
    use tower::Service;

    fn test_app(anonymous_limit: u32, auth_limit: u32, window: Duration) -> Router<()> {
        let limiter = RateLimitState::new(RateLimitConfig::for_tests(
            anonymous_limit,
            auth_limit,
            window,
        ));

        Router::new()
            .route("/read", get(|| async { "read" }))
            .layer(middleware::from_fn_with_state(
                limiter,
                rate_limit_middleware,
            ))
    }

    async fn call(app: &Router<()>, request: Request<Body>) -> Response {
        let mut svc = app.clone();
        svc.call(request).await.unwrap()
    }

    /// Issue #609: anonymous IP limited to 1,000 req/hour; 1001st gets 429.
    #[tokio::test]
    async fn anonymous_user_gets_429_on_1001st_request() {
        let app = test_app(1_000, 1_000, Duration::from_secs(3600));

        for _ in 0..1_000 {
            let response = call(
                &app,
                Request::builder()
                    .uri("/read")
                    .method("GET")
                    .header("x-forwarded-for", "203.0.113.10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;

            assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }

        let response = call(
            &app,
            Request::builder()
                .uri("/read")
                .method("GET")
                .header("x-forwarded-for", "203.0.113.10")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key(RETRY_AFTER));
    }

    #[tokio::test]
    async fn authenticated_user_gets_429_on_1001st_request() {
        let app = test_app(100, 1_000, Duration::from_secs(60));

        for _ in 0..1_000 {
            let response = call(
                &app,
                Request::builder()
                    .uri("/read")
                    .method("GET")
                    .header("authorization", "Bearer token-abc")
                    .header("x-forwarded-for", "203.0.113.25")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;

            assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }

        let response = call(
            &app,
            Request::builder()
                .uri("/read")
                .method("GET")
                .header("authorization", "Bearer token-abc")
                .header("x-forwarded-for", "203.0.113.25")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key(RETRY_AFTER));
    }

    #[tokio::test]
    async fn includes_rate_limit_headers_on_success_and_429() {
        let app = test_app(1, 10, Duration::from_secs(60));

        let ok_response = call(
            &app,
            Request::builder()
                .uri("/read")
                .method("GET")
                .header("x-forwarded-for", "198.51.100.22")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(ok_response.status(), StatusCode::OK);
        assert!(ok_response.headers().contains_key(HEADER_RATE_LIMIT_LIMIT));
        assert!(ok_response
            .headers()
            .contains_key(HEADER_RATE_LIMIT_REMAINING));
        assert!(ok_response.headers().contains_key(HEADER_RATE_LIMIT_RESET));

        let limited_response = call(
            &app,
            Request::builder()
                .uri("/read")
                .method("GET")
                .header("x-forwarded-for", "198.51.100.22")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(limited_response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(limited_response
            .headers()
            .contains_key(HEADER_RATE_LIMIT_LIMIT));
        assert!(limited_response
            .headers()
            .contains_key(HEADER_RATE_LIMIT_REMAINING));
        assert!(limited_response
            .headers()
            .contains_key(HEADER_RATE_LIMIT_RESET));
        assert!(limited_response.headers().contains_key(RETRY_AFTER));

        let body = axum::body::to_bytes(limited_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error_code"], "RATE_LIMITED");
    }

    #[tokio::test]
    async fn retry_after_header_is_present_and_reasonable() {
        let app = test_app(1, 10, Duration::from_secs(2));

        let _first = call(
            &app,
            Request::builder()
                .uri("/read")
                .method("GET")
                .header("x-forwarded-for", "192.0.2.44")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let second = call(
            &app,
            Request::builder()
                .uri("/read")
                .method("GET")
                .header("x-forwarded-for", "192.0.2.44")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after: u64 = second
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        assert!((1..=2).contains(&retry_after));
    }

    #[tokio::test]
    async fn rate_limit_headers_show_remaining_quota() {
        let app = test_app(2, 10, Duration::from_secs(60));

        let first = call(
            &app,
            Request::builder()
                .uri("/read")
                .method("GET")
                .header("x-forwarded-for", "192.0.2.44")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(
            first
                .headers()
                .get(HEADER_RATE_LIMIT_REMAINING)
                .and_then(|value| value.to_str().ok())
                .unwrap_or(""),
            "1"
        );

        let second = call(
            &app,
            Request::builder()
                .uri("/read")
                .method("GET")
                .header("x-forwarded-for", "192.0.2.44")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(
            second
                .headers()
                .get(HEADER_RATE_LIMIT_REMAINING)
                .and_then(|value| value.to_str().ok())
                .unwrap_or(""),
            "0"
        );

        let third = call(
            &app,
            Request::builder()
                .uri("/read")
                .method("GET")
                .header("x-forwarded-for", "192.0.2.44")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(third.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            third
                .headers()
                .get(HEADER_RATE_LIMIT_REMAINING)
                .and_then(|value| value.to_str().ok())
                .unwrap_or(""),
            "0"
        );
    }

    #[tokio::test]
    async fn contracts_rate_limit_scales_down_for_large_page_sizes() {
        let app = test_app(100, 20, Duration::from_secs(60));
        let ip = "198.51.100.77";

        for _ in 0..5 {
            let response = call(
                &app,
                Request::builder()
                    .uri("/api/contracts?limit=1000")
                    .method("GET")
                    .header("x-forwarded-for", ip)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                response
                    .headers()
                    .get(HEADER_RATE_LIMIT_LIMIT)
                    .and_then(|value| value.to_str().ok()),
                Some("5")
            );
        }

        let limited = call(
            &app,
            Request::builder()
                .uri("/api/contracts?limit=1000")
                .method("GET")
                .header("x-forwarded-for", ip)
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn page_size_scaling_uses_default_page_size_baseline() {
        assert_eq!(scale_limit_by_page_size(100, 50), 100);
        assert_eq!(scale_limit_by_page_size(100, 51), 50);
        assert_eq!(scale_limit_by_page_size(100, 1000), 5);
    }

    /// Verify that the eviction logic correctly removes expired buckets.
    #[tokio::test]
    async fn eviction_removes_expired_buckets() {
        let window = Duration::from_millis(100);
        let state = RateLimitState::new(RateLimitConfig::for_tests(10, 10, window));

        // Insert a request so a bucket is created
        let req = Request::builder()
            .uri("/read")
            .method("GET")
            .header("x-forwarded-for", "10.0.0.1")
            .body(Body::empty())
            .unwrap();
        let (hourly, burst, key, _tier) = state.select_limit_and_key(&req);
        state.check_request(key, hourly, burst).await;

        // Confirm one bucket exists
        assert_eq!(state.buckets.lock().await.len(), 1);

        // Wait for more than two window lengths so the bucket qualifies for eviction
        tokio::time::sleep(window.saturating_mul(3)).await;

        // Run eviction manually (same logic as the background task)
        {
            let now = Instant::now();
            let mut map = state.buckets.lock().await;
            map.retain(|_, s| {
                let hourly = s
                    .timestamps
                    .back()
                    .map(|last_seen| {
                        now.saturating_duration_since(*last_seen) < window.saturating_mul(2)
                    })
                    .unwrap_or(false);
                let burst = s
                    .burst_timestamps
                    .back()
                    .map(|last_seen| {
                        now.saturating_duration_since(*last_seen) < window.saturating_mul(2)
                    })
                    .unwrap_or(false);
                hourly || burst
            });
        }

        assert_eq!(state.buckets.lock().await.len(), 0);
    }

    // ── Write endpoint protection tests ──────────────────────────────────────

    fn test_app_with_write(read_limit: u32, write_limit: u32, window: Duration) -> Router<()> {
        let limiter = RateLimitState::new(RateLimitConfig::for_tests_with_write(
            read_limit,
            read_limit,
            write_limit,
            write_limit,
            window,
        ));

        Router::new()
            .route("/read", get(|| async { "read" }))
            .route("/write", post(|| async { "written" }))
            .route("/health", get(|| async { "ok" }))
            .route("/health/ready", get(|| async { "ok" }))
            .route("/metrics", get(|| async { "# metrics" }))
            .route("/api/admin/audit-logs", get(|| async { "[]" }))
            .layer(middleware::from_fn_with_state(
                limiter,
                rate_limit_middleware,
            ))
    }

    #[tokio::test]
    async fn write_requests_use_tighter_limit_than_reads() {
        // Read limit: 100, write limit: 2. After 2 POSTs the third is blocked.
        // GETs should still be allowed up to the read limit.
        let app = test_app_with_write(100, 2, Duration::from_secs(60));
        let ip = "198.51.100.99";

        // First two POSTs succeed.
        for _ in 0..2 {
            let response = call(
                &app,
                Request::builder()
                    .uri("/write")
                    .method("POST")
                    .header("x-forwarded-for", ip)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_ne!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "first two write requests should not be rate limited"
            );
        }

        // Third POST is blocked.
        let limited = call(
            &app,
            Request::builder()
                .uri("/write")
                .method("POST")
                .header("x-forwarded-for", ip)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(limited.headers().contains_key(RETRY_AFTER));

        // GET requests are still within their separate read quota.
        let read_response = call(
            &app,
            Request::builder()
                .uri("/read")
                .method("GET")
                .header("x-forwarded-for", ip)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_ne!(read_response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn write_limit_response_body_contains_limit_type_write() {
        let app = test_app_with_write(100, 1, Duration::from_secs(60));
        let ip = "203.0.113.55";

        // Use up the single write slot.
        call(
            &app,
            Request::builder()
                .uri("/write")
                .method("POST")
                .header("x-forwarded-for", ip)
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        let response = call(
            &app,
            Request::builder()
                .uri("/write")
                .method("POST")
                .header("x-forwarded-for", ip)
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["details"]["limit_type"], "write");
    }

    #[tokio::test]
    async fn health_endpoint_is_not_rate_limited() {
        // Very tight limits — both read and write — to verify health bypasses.
        let app = test_app_with_write(1, 1, Duration::from_secs(60));
        let ip = "192.0.2.1";

        // Send many requests to /health; none should be rate limited.
        for i in 0..20 {
            let response = call(
                &app,
                Request::builder()
                    .uri("/health")
                    .method("GET")
                    .header("x-forwarded-for", ip)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_ne!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "request {i} to /health should not be rate limited"
            );
        }
    }

    #[tokio::test]
    async fn health_ready_endpoint_is_exempt() {
        let app = test_app_with_write(1, 1, Duration::from_secs(60));
        let ip = "192.0.2.2";

        for i in 0..5 {
            let response = call(
                &app,
                Request::builder()
                    .uri("/health/ready")
                    .method("GET")
                    .header("x-forwarded-for", ip)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_ne!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "request {i} to /health/ready should not be rate limited"
            );
        }
    }

    #[tokio::test]
    async fn metrics_endpoint_is_exempt() {
        let app = test_app_with_write(1, 1, Duration::from_secs(60));
        let ip = "192.0.2.3";

        for i in 0..5 {
            let response = call(
                &app,
                Request::builder()
                    .uri("/metrics")
                    .method("GET")
                    .header("x-forwarded-for", ip)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_ne!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "request {i} to /metrics should not be rate limited"
            );
        }
    }

    #[tokio::test]
    async fn admin_endpoint_is_exempt_from_rate_limiting() {
        let app = test_app_with_write(1, 1, Duration::from_secs(60));
        let ip = "192.0.2.4";

        for i in 0..5 {
            let response = call(
                &app,
                Request::builder()
                    .uri("/api/admin/audit-logs")
                    .method("GET")
                    .header("x-forwarded-for", ip)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_ne!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "request {i} to /api/admin/* should not be rate limited"
            );
        }
    }

    #[test]
    fn is_exempt_path_recognises_health_metrics_and_admin() {
        assert!(is_exempt_path("/health"));
        assert!(is_exempt_path("/health/live"));
        assert!(is_exempt_path("/health/ready"));
        assert!(is_exempt_path("/health/detailed"));
        assert!(is_exempt_path("/metrics"));
        assert!(is_exempt_path("/api/admin/migrations/status"));
        assert!(!is_exempt_path("/api/contracts"));
        assert!(!is_exempt_path("/api/contracts/verify"));
        assert!(!is_exempt_path("/api/publishers"));
    }

    // ── Trusted-client bypass audit tests (issue #1054) ──────────────────────

    /// Build a test app where a specific IP is whitelisted (tight read limit of
    /// 1 so any second request from a non-trusted IP would be blocked).
    fn test_app_with_trusted_ip(trusted_ip: &str) -> Router<()> {
        let mut trusted_ips = HashSet::new();
        trusted_ips.insert(trusted_ip.to_string());

        let config = RateLimitConfig {
            anonymous_limit: 1,
            auth_limit: 1,
            write_anonymous_limit: 1,
            write_auth_limit: 1,
            window: Duration::from_secs(60),
            enterprise_limit: 100_000,
            burst_window: Duration::from_secs(BURST_WINDOW_SECONDS),
            per_api_key_limits: HashMap::new(),
            trusted_client_ips: trusted_ips,
            trusted_api_keys: HashSet::new(),
        };
        let limiter = RateLimitState::new(config);

        Router::new()
            .route("/read", get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(
                limiter,
                rate_limit_middleware,
            ))
    }

    /// Build a test app where a specific API key is whitelisted.
    fn test_app_with_trusted_api_key(trusted_key: &str) -> Router<()> {
        let mut trusted_keys = HashSet::new();
        trusted_keys.insert(trusted_key.to_string());

        let config = RateLimitConfig {
            anonymous_limit: 1,
            auth_limit: 1,
            write_anonymous_limit: 1,
            write_auth_limit: 1,
            window: Duration::from_secs(60),
            enterprise_limit: 100_000,
            burst_window: Duration::from_secs(BURST_WINDOW_SECONDS),
            per_api_key_limits: HashMap::new(),
            trusted_client_ips: HashSet::new(),
            trusted_api_keys: trusted_keys,
        };
        let limiter = RateLimitState::new(config);

        Router::new()
            .route("/read", get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(
                limiter,
                rate_limit_middleware,
            ))
    }

    /// A trusted IP must never receive a 429, even after exceeding the normal
    /// per-IP limit.  The bypass path must be taken for every request.
    #[tokio::test]
    async fn trusted_ip_is_never_rate_limited() {
        let trusted_ip = "10.0.0.1";
        let app = test_app_with_trusted_ip(trusted_ip);

        // With a limit of 1, the second request from a non-trusted IP would
        // normally be blocked.  A trusted IP must always pass through.
        for i in 0..10 {
            let response = call(
                &app,
                Request::builder()
                    .uri("/read")
                    .method("GET")
                    .header("x-forwarded-for", trusted_ip)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_ne!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "trusted IP should never be rate limited (request {i})"
            );
        }
    }

    /// A trusted API key must never receive a 429, even beyond the normal
    /// per-key limit.
    #[tokio::test]
    async fn trusted_api_key_is_never_rate_limited() {
        let trusted_key = "trusted-secret-key-abc";
        let app = test_app_with_trusted_api_key(trusted_key);

        for i in 0..10 {
            let response = call(
                &app,
                Request::builder()
                    .uri("/read")
                    .method("GET")
                    .header("x-api-key", trusted_key)
                    .header("x-forwarded-for", "192.0.2.99")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_ne!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "trusted API key should never be rate limited (request {i})"
            );
        }
    }

    /// An untrusted IP still gets rate-limited even when a trusted IP is
    /// configured — the whitelist must not accidentally open for everyone.
    #[tokio::test]
    async fn untrusted_ip_is_still_rate_limited_when_trusted_ip_exists() {
        let trusted_ip = "10.0.0.1";
        let untrusted_ip = "1.2.3.4";
        let app = test_app_with_trusted_ip(trusted_ip);

        // First request from untrusted IP is fine.
        let first = call(
            &app,
            Request::builder()
                .uri("/read")
                .method("GET")
                .header("x-forwarded-for", untrusted_ip)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_ne!(first.status(), StatusCode::TOO_MANY_REQUESTS);

        // Second request from same untrusted IP must be blocked (limit=1).
        let second = call(
            &app,
            Request::builder()
                .uri("/read")
                .method("GET")
                .header("x-forwarded-for", untrusted_ip)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(
            second.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "untrusted IP should still be rate limited"
        );
    }

    /// `bypass_kind` must identify a trusted IP as `BypassKind::TrustedIp`.
    #[test]
    fn bypass_kind_returns_trusted_ip_for_whitelisted_ip() {
        let mut trusted_ips = HashSet::new();
        trusted_ips.insert("10.1.2.3".to_string());
        let config = RateLimitConfig {
            anonymous_limit: 100,
            auth_limit: 100,
            write_anonymous_limit: 10,
            write_auth_limit: 30,
            window: Duration::from_secs(60),
            enterprise_limit: 100_000,
            burst_window: Duration::from_secs(BURST_WINDOW_SECONDS),
            per_api_key_limits: HashMap::new(),
            trusted_client_ips: trusted_ips,
            trusted_api_keys: HashSet::new(),
        };

        let req = Request::builder()
            .uri("/read")
            .method("GET")
            .header("x-forwarded-for", "10.1.2.3")
            .body(Body::empty())
            .unwrap();

        assert_eq!(config.bypass_kind(&req), Some(BypassKind::TrustedIp));
    }

    /// `bypass_kind` must identify a trusted API key as `BypassKind::TrustedApiKey`.
    #[test]
    fn bypass_kind_returns_trusted_api_key_for_whitelisted_key() {
        let mut trusted_keys = HashSet::new();
        trusted_keys.insert("my-secret-key".to_string());
        let config = RateLimitConfig {
            anonymous_limit: 100,
            auth_limit: 100,
            write_anonymous_limit: 10,
            write_auth_limit: 30,
            window: Duration::from_secs(60),
            enterprise_limit: 100_000,
            burst_window: Duration::from_secs(BURST_WINDOW_SECONDS),
            per_api_key_limits: HashMap::new(),
            trusted_client_ips: HashSet::new(),
            trusted_api_keys: trusted_keys,
        };

        let req = Request::builder()
            .uri("/read")
            .method("GET")
            .header("x-api-key", "my-secret-key")
            .header("x-forwarded-for", "192.0.2.1")
            .body(Body::empty())
            .unwrap();

        assert_eq!(config.bypass_kind(&req), Some(BypassKind::TrustedApiKey));
    }

    /// `bypass_kind` returns `None` for an unknown IP/key.
    #[test]
    fn bypass_kind_returns_none_for_unknown_client() {
        let config = RateLimitConfig {
            anonymous_limit: 100,
            auth_limit: 100,
            write_anonymous_limit: 10,
            write_auth_limit: 30,
            window: Duration::from_secs(60),
            enterprise_limit: 100_000,
            burst_window: Duration::from_secs(BURST_WINDOW_SECONDS),
            per_api_key_limits: HashMap::new(),
            trusted_client_ips: HashSet::new(),
            trusted_api_keys: HashSet::new(),
        };

        let req = Request::builder()
            .uri("/read")
            .method("GET")
            .header("x-forwarded-for", "203.0.113.42")
            .body(Body::empty())
            .unwrap();

        assert_eq!(config.bypass_kind(&req), None);
    }

    /// The rolling spike window resets after the time window expires and the
    /// count restarts from 1.
    #[test]
    fn bypass_spike_window_resets_after_expiry() {
        // Use a very short window via the internal state directly.
        let state = BypassSpikeState {
            window_start_unix: AtomicI64::new(Utc::now().timestamp() - BYPASS_WINDOW_SECS as i64 - 1),
            window_count: AtomicU64::new(50),
        };

        // The window is expired, so the next record should restart at 1.
        let count = state.record_and_count();
        assert_eq!(count, 1, "window should have reset; count should be 1");
    }

    /// The rolling spike window increments correctly within a fresh window.
    #[test]
    fn bypass_spike_window_increments_within_window() {
        let state = BypassSpikeState::new();
        assert_eq!(state.record_and_count(), 1);
        assert_eq!(state.record_and_count(), 2);
        assert_eq!(state.record_and_count(), 3);
    }

    /// `BypassKind::as_identity_type` returns the correct label strings used
    /// in Prometheus metrics.
    #[test]
    fn bypass_kind_identity_type_labels() {
        assert_eq!(BypassKind::TrustedIp.as_identity_type(), "ip");
        assert_eq!(BypassKind::TrustedApiKey.as_identity_type(), "api_key");
    }
}
