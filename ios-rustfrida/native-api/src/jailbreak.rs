use common::Result;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookBackendInfo {
    pub id: String,
    pub display_name: String,
    pub loaded_images: Vec<String>,
    pub filesystem_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookEnvironmentReport {
    pub active_backend: Option<String>,
    pub backends: Vec<HookBackendInfo>,
    pub warnings: Vec<String>,
}

impl HookEnvironmentReport {
    pub fn loaded_backend_count(&self) -> usize {
        self.backends
            .iter()
            .filter(|backend| !backend.loaded_images.is_empty())
            .count()
    }

    pub fn filesystem_only_backend_count(&self) -> usize {
        self.backends
            .iter()
            .filter(|backend| backend.loaded_images.is_empty() && !backend.filesystem_paths.is_empty())
            .count()
    }

    pub fn loaded_image_count(&self) -> usize {
        self.backends.iter().map(|backend| backend.loaded_images.len()).sum()
    }

    pub fn filesystem_path_count(&self) -> usize {
        self.backends
            .iter()
            .map(|backend| backend.filesystem_paths.len())
            .sum()
    }

    pub fn conflict_state(&self) -> &'static str {
        match self.loaded_backend_count() {
            count if count > 1 => "multiple-loaded",
            1 => "external-loaded",
            _ if self.filesystem_path_count() > 0 => "filesystem-only",
            _ => "none",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookPolicy {
    Warn,
    QueryOnlyExternalLoaded,
    DenyExternalLoaded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookStrategyDecision {
    pub policy: HookPolicy,
    pub strategy: String,
    pub allowed: bool,
    pub inline_hooks_allowed: bool,
    pub reason: Option<String>,
}

impl HookStrategyDecision {
    fn cleanup_commands_only_mode(&self) -> bool {
        matches!(self.policy, HookPolicy::DenyExternalLoaded) && !self.allowed && !self.inline_hooks_allowed
    }

    pub fn bootstrap_injection_allowed(&self) -> bool {
        self.allowed || self.cleanup_commands_only_mode()
    }

    pub fn query_commands_allowed(&self) -> bool {
        self.allowed
    }

    pub fn hook_install_commands_allowed(&self) -> bool {
        self.allowed && self.inline_hooks_allowed
    }

    pub fn hook_status_commands_allowed(&self) -> bool {
        self.allowed || self.cleanup_commands_only_mode()
    }

    pub fn hook_stop_commands_allowed(&self) -> bool {
        self.allowed || self.cleanup_commands_only_mode()
    }

    pub fn command_mode(&self) -> &'static str {
        if self.hook_install_commands_allowed() {
            "allowed"
        } else if self.query_commands_allowed() {
            "query-only"
        } else if self.hook_status_commands_allowed() || self.hook_stop_commands_allowed() {
            "cleanup-only"
        } else {
            "blocked"
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookRecommendedAction {
    pub command_group: String,
    pub action_key: String,
    pub priority: u8,
    pub allowed: bool,
    pub status: String,
    pub recommendation: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookCoexistenceLayerStatus {
    pub available: bool,
    pub status: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct KnownHookBackend {
    id: &'static str,
    display_name: &'static str,
    image_markers: &'static [&'static str],
    filesystem_paths: &'static [&'static str],
}

const ELLEKIT_PATHS: &[&str] = &[
    "/var/jb/usr/lib/libellekit.dylib",
    "/usr/lib/libellekit.dylib",
    "/var/jb/Library/MobileSubstrate/DynamicLibraries/ElleKit.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/ElleKit.dylib",
];
const SUBSTRATE_PATHS: &[&str] = &[
    "/var/jb/usr/lib/libsubstrate.dylib",
    "/usr/lib/libsubstrate.dylib",
    "/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
    "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
    "/var/jb/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
];
const SUBSTITUTE_PATHS: &[&str] = &[
    "/var/jb/usr/lib/libsubstitute.dylib",
    "/usr/lib/libsubstitute.dylib",
    "/var/jb/Library/Frameworks/Substitute.framework/Substitute",
    "/Library/Frameworks/Substitute.framework/Substitute",
];
const LIBHOOKER_PATHS: &[&str] = &[
    "/var/jb/usr/lib/libhooker.dylib",
    "/usr/lib/libhooker.dylib",
    "/var/jb/Library/Frameworks/libhooker.framework/libhooker",
    "/Library/Frameworks/libhooker.framework/libhooker",
];

const KNOWN_HOOK_BACKENDS: &[KnownHookBackend] = &[
    KnownHookBackend {
        id: "ellekit",
        display_name: "ElleKit",
        image_markers: &["ellekit"],
        filesystem_paths: ELLEKIT_PATHS,
    },
    KnownHookBackend {
        id: "substrate",
        display_name: "Cydia Substrate",
        image_markers: &["substrate", "mobilesubstrate", "cydiasubstrate"],
        filesystem_paths: SUBSTRATE_PATHS,
    },
    KnownHookBackend {
        id: "substitute",
        display_name: "Substitute",
        image_markers: &["substitute"],
        filesystem_paths: SUBSTITUTE_PATHS,
    },
    KnownHookBackend {
        id: "libhooker",
        display_name: "libhooker",
        image_markers: &["libhooker"],
        filesystem_paths: LIBHOOKER_PATHS,
    },
];

pub fn detect_hook_environment() -> Result<HookEnvironmentReport> {
    let image_names = crate::enumerate_images()
        .map(|images| images.into_iter().map(|image| image.name).collect::<Vec<_>>())
        .unwrap_or_default();
    Ok(detect_hook_environment_with(&image_names, |path| {
        Path::new(path).exists()
    }))
}

pub fn current_hook_policy() -> HookPolicy {
    match std::env::var("IOS_RUSTFRIDA_HOOK_POLICY") {
        Ok(raw) => HookPolicy::parse(&raw).unwrap_or(HookPolicy::Warn),
        Err(_) => HookPolicy::Warn,
    }
}

pub fn resolve_hook_strategy() -> Result<HookStrategyDecision> {
    let report = detect_hook_environment()?;
    Ok(resolve_hook_strategy_with_report(&report, current_hook_policy()))
}

pub fn hook_environment_recommendations(
    report: &HookEnvironmentReport,
    decision: Option<&HookStrategyDecision>,
) -> Vec<String> {
    recommendations_for_report(report, decision)
}

pub fn hook_environment_recommended_actions(
    report: &HookEnvironmentReport,
    decision: Option<&HookStrategyDecision>,
) -> Vec<HookRecommendedAction> {
    let loaded_backend_detected = report.loaded_backend_count() > 0;
    let filesystem_candidates_detected = report.filesystem_only_backend_count() > 0;
    let mode = decision
        .map(HookStrategyDecision::command_mode)
        .unwrap_or("allowed");
    let reason = decision.and_then(|item| item.reason.clone());

    let mut actions = [
        ("bootstrap", decision.map(|item| item.bootstrap_injection_allowed()).unwrap_or(true)),
        ("query", decision.map(|item| item.query_commands_allowed()).unwrap_or(true)),
        (
            "hook-install",
            decision
                .map(|item| item.hook_install_commands_allowed())
                .unwrap_or(true),
        ),
        (
            "hook-status",
            decision
                .map(|item| item.hook_status_commands_allowed())
                .unwrap_or(true),
        ),
        ("hook-stop", decision.map(|item| item.hook_stop_commands_allowed()).unwrap_or(true)),
    ]
    .into_iter()
    .map(|(command_group, allowed)| HookRecommendedAction {
        command_group: command_group.into(),
        action_key: action_key_for_command_group(command_group).into(),
        priority: action_priority(mode, command_group, allowed),
        allowed,
        status: if allowed { "allowed".into() } else { "blocked".into() },
        recommendation: recommendation_for_action(
            command_group,
            allowed,
            mode,
            loaded_backend_detected,
            filesystem_candidates_detected,
        ),
        reason: reason.clone(),
    })
    .collect::<Vec<_>>();

    actions.sort_by_key(|action| (action.priority, command_group_sort_order(&action.command_group)));
    actions
}

pub fn hook_coexistence_layer_status(
    report: &HookEnvironmentReport,
    decision: Option<&HookStrategyDecision>,
) -> HookCoexistenceLayerStatus {
    hook_coexistence_layer_status_for_mode(
        decision.map(HookStrategyDecision::command_mode),
        report.loaded_backend_count() > 0,
        report.filesystem_only_backend_count() > 0,
    )
}

pub fn hook_coexistence_layer_status_for_mode(
    command_mode: Option<&str>,
    external_backend_loaded: bool,
    filesystem_only_backend_detected: bool,
) -> HookCoexistenceLayerStatus {
    if !external_backend_loaded {
        return HookCoexistenceLayerStatus {
            available: true,
            status: if filesystem_only_backend_detected {
                "not-required-filesystem-only"
            } else {
                "not-required"
            },
        };
    }

    let status = match command_mode {
        Some("allowed") => "missing-inline-risky",
        Some("query-only") => "missing-query-only",
        Some("cleanup-only") => "missing-cleanup-only",
        Some("blocked") => "missing-blocked",
        _ => "missing-unknown",
    };

    HookCoexistenceLayerStatus {
        available: false,
        status,
    }
}

#[allow(dead_code)]
pub(crate) fn detect_hook_environment_from_image_names(image_names: &[String]) -> HookEnvironmentReport {
    detect_hook_environment_with(image_names, |_| false)
}

#[allow(dead_code)]
pub(crate) fn resolve_hook_strategy_for_report(
    report: &HookEnvironmentReport,
    policy: HookPolicy,
) -> HookStrategyDecision {
    resolve_hook_strategy_with_report(report, policy)
}

fn detect_hook_environment_with<F>(image_names: &[String], path_exists: F) -> HookEnvironmentReport
where
    F: Fn(&str) -> bool,
{
    let mut backends = Vec::new();
    for backend in KNOWN_HOOK_BACKENDS {
        let loaded_images = detect_loaded_images(image_names, backend.image_markers);
        let filesystem_paths = backend
            .filesystem_paths
            .iter()
            .copied()
            .filter(|path| path_exists(path))
            .map(str::to_string)
            .collect::<Vec<_>>();

        if loaded_images.is_empty() && filesystem_paths.is_empty() {
            continue;
        }

        backends.push(HookBackendInfo {
            id: backend.id.to_string(),
            display_name: backend.display_name.to_string(),
            loaded_images,
            filesystem_paths,
        });
    }

    let active_backend = backends
        .iter()
        .find(|backend| !backend.loaded_images.is_empty())
        .map(|backend| backend.id.clone());

    let loaded_count = backends
        .iter()
        .filter(|backend| !backend.loaded_images.is_empty())
        .count();
    let mut warnings = Vec::new();
    if loaded_count > 1 {
        warnings.push(
            "multiple hook ecosystems are loaded; coexistence is not implemented yet and symbol conflicts are possible"
                .into(),
        );
    } else if loaded_count == 1 {
        warnings.push(
            "external hook ecosystem detected; ios-rustfrida does not yet provide a coexistence layer or alternate backend integration"
                .into(),
        );
    } else if !backends.is_empty() {
        warnings.push(
            "hook ecosystem files are present on disk, but no known backend image is loaded in the current process"
                .into(),
        );
    }

    HookEnvironmentReport {
        active_backend,
        backends,
        warnings,
    }
}

fn detect_loaded_images(image_names: &[String], markers: &[&str]) -> Vec<String> {
    let mut matches = image_names
        .iter()
        .filter(|image_name| {
            let lower = image_name.to_ascii_lowercase();
            markers.iter().any(|marker| lower.contains(marker))
        })
        .cloned()
        .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();
    matches
}

impl HookPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            HookPolicy::Warn => "warn",
            HookPolicy::QueryOnlyExternalLoaded => "query-only-external-loaded",
            HookPolicy::DenyExternalLoaded => "deny-external-loaded",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "warn" => Some(HookPolicy::Warn),
            "query-only-external-loaded" | "query_only_external_loaded" | "query-only" | "query_only" => {
                Some(HookPolicy::QueryOnlyExternalLoaded)
            }
            "deny-external-loaded" | "deny_external_loaded" | "deny" => Some(HookPolicy::DenyExternalLoaded),
            _ => None,
        }
    }
}

fn resolve_hook_strategy_with_report(report: &HookEnvironmentReport, policy: HookPolicy) -> HookStrategyDecision {
    let has_loaded_external_backend = report.backends.iter().any(|backend| !backend.loaded_images.is_empty());

    if has_loaded_external_backend {
        return match policy {
            HookPolicy::Warn => HookStrategyDecision {
                policy,
                strategy: "internal-inline-risky".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: Some(
                    "external hook backend is already loaded; ios-rustfrida will still use its internal inline hook engine, but coexistence is not implemented".into(),
                ),
            },
            HookPolicy::QueryOnlyExternalLoaded => HookStrategyDecision {
                policy,
                strategy: "query-only-external-loaded".into(),
                allowed: true,
                inline_hooks_allowed: false,
                reason: Some(
                    "external hook backend is already loaded; query-only injection remains allowed, but ios-rustfrida inline hooks are disabled under the current policy".into(),
                ),
            },
            HookPolicy::DenyExternalLoaded => HookStrategyDecision {
                policy,
                strategy: "cleanup-only-external-loaded".into(),
                allowed: false,
                inline_hooks_allowed: false,
                reason: Some(
                    "external hook backend is already loaded; current policy blocks query/install commands but still allows status/stop cleanup commands".into(),
                ),
            },
        };
    }

    if report
        .backends
        .iter()
        .any(|backend| !backend.filesystem_paths.is_empty())
    {
        return HookStrategyDecision {
            policy,
            strategy: "internal-inline-cautious".into(),
            allowed: true,
            inline_hooks_allowed: true,
            reason: Some(
                "hook ecosystem files are present on disk, but no known backend image is loaded in the current process"
                    .into(),
            ),
        };
    }

    HookStrategyDecision {
        policy,
        strategy: "internal-inline".into(),
        allowed: true,
        inline_hooks_allowed: true,
        reason: None,
    }
}

fn recommendations_for_report(report: &HookEnvironmentReport, decision: Option<&HookStrategyDecision>) -> Vec<String> {
    let loaded_backend_count = report
        .backends
        .iter()
        .filter(|backend| !backend.loaded_images.is_empty())
        .count();
    let filesystem_only_backend_count = report
        .backends
        .iter()
        .filter(|backend| backend.loaded_images.is_empty() && !backend.filesystem_paths.is_empty())
        .count();

    let mut recommendations = Vec::new();

    if loaded_backend_count > 1 {
        recommendations.push(
            "multiple external hook backends are loaded; reduce the target to a single hook ecosystem before enabling ios-rustfrida inline hooks".into(),
        );
    }

    if let Some(decision) = decision {
        if !decision.bootstrap_injection_allowed() {
            recommendations.push(
                "current hook policy blocks inline hooks in this process; use query-only commands or explicitly relax IOS_RUSTFRIDA_HOOK_POLICY if you accept coexistence risk".into(),
            );
        } else if !decision.query_commands_allowed()
            && (decision.hook_status_commands_allowed() || decision.hook_stop_commands_allowed())
        {
            recommendations.push(
                "current hook policy allows cleanup-only mode; use trace/stalker/jhook/shook/hfl status/stop to recover state, but avoid query/install commands unless you relax IOS_RUSTFRIDA_HOOK_POLICY".into(),
            );
        } else if !decision.inline_hooks_allowed {
            recommendations.push(
                "injection/query-only commands remain allowed, but inline hooks are disabled under the current policy; avoid trace/stalker/jhook/shook unless you relax IOS_RUSTFRIDA_HOOK_POLICY".into(),
            );
        } else if loaded_backend_count > 0 {
            recommendations.push(
                "inline hooks are allowed but risky with an external backend already loaded; validate on a sacrificial target before using trace/stalker/jhook/shook on a real app".into(),
            );
        }
    } else if loaded_backend_count > 0 {
        recommendations.push(
            "an external hook backend is loaded; resolve hook policy before relying on ios-rustfrida inline hooks"
                .into(),
        );
    }

    if loaded_backend_count == 0 && filesystem_only_backend_count > 0 {
        recommendations.push(
            "hook backend files exist on disk but are not loaded in this process; confirm the target image list at runtime before assuming coexistence constraints".into(),
        );
    }

    recommendations
}

fn recommendation_for_action(
    command_group: &str,
    allowed: bool,
    mode: &str,
    loaded_backend_detected: bool,
    filesystem_candidates_detected: bool,
) -> String {
    if !allowed {
        return match (mode, command_group) {
            ("query-only", "hook-install") => {
                "blocked by query-only mode; install commands are disabled while an external backend is loaded".into()
            }
            ("cleanup-only", "query") | ("cleanup-only", "hook-install") => {
                "blocked by cleanup-only mode; use status/stop for cleanup or relax IOS_RUSTFRIDA_HOOK_POLICY".into()
            }
            ("blocked", _) => {
                "blocked by current hook policy; relax IOS_RUSTFRIDA_HOOK_POLICY only if coexistence risk is acceptable".into()
            }
            _ => "blocked by current hook strategy".into(),
        };
    }

    match (mode, command_group) {
        ("cleanup-only", "hook-status") | ("cleanup-only", "hook-stop") => {
            "allowed in cleanup-only mode; use these commands to inspect and recover hook state".into()
        }
        (_, "hook-install") if loaded_backend_detected => {
            "allowed but risky with external backend loaded; validate on a sacrificial target before production apps".into()
        }
        (_, "hook-install") if filesystem_candidates_detected => {
            "allowed; backend files exist on disk but no known backend image is loaded in this process".into()
        }
        (_, "query") => "allowed; prefer query commands first when diagnosing hook conflicts".into(),
        _ => "allowed under current hook policy".into(),
    }
}

fn action_priority(mode: &str, command_group: &str, allowed: bool) -> u8 {
    if !allowed {
        return match (mode, command_group) {
            ("cleanup-only", "query" | "hook-install") => 4,
            ("query-only", "hook-install") => 4,
            ("blocked", _) => 5,
            _ => 4,
        };
    }

    match mode {
        "cleanup-only" => match command_group {
            "hook-status" | "hook-stop" => 1,
            "bootstrap" => 2,
            _ => 3,
        },
        "query-only" => match command_group {
            "query" => 1,
            "bootstrap" | "hook-status" | "hook-stop" => 2,
            "hook-install" => 4,
            _ => 3,
        },
        _ => match command_group {
            "query" => 1,
            "bootstrap" => 2,
            "hook-install" | "hook-status" | "hook-stop" => 3,
            _ => 3,
        },
    }
}

fn action_key_for_command_group(command_group: &str) -> &'static str {
    match command_group {
        "bootstrap" => "hook.bootstrap",
        "query" => "hook.query",
        "hook-install" => "hook.install",
        "hook-status" => "hook.status",
        "hook-stop" => "hook.stop",
        _ => "hook.unknown",
    }
}

fn command_group_sort_order(command_group: &str) -> u8 {
    match command_group {
        "bootstrap" => 0,
        "query" => 1,
        "hook-install" => 2,
        "hook-status" => 3,
        "hook-stop" => 4,
        _ => u8::MAX,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        detect_hook_environment_with, hook_coexistence_layer_status, hook_coexistence_layer_status_for_mode,
        hook_environment_recommendations, hook_environment_recommended_actions, resolve_hook_strategy_with_report,
        HookEnvironmentReport, HookPolicy,
    };

    #[test]
    fn detects_loaded_ellekit_images() {
        let images = vec![
            "/usr/lib/libSystem.B.dylib".to_string(),
            "/usr/lib/libellekit.dylib".to_string(),
        ];

        let report = detect_hook_environment_with(&images, |_| false);
        assert_eq!(report.active_backend.as_deref(), Some("ellekit"));
        assert_eq!(report.backends.len(), 1);
        assert_eq!(report.backends[0].id, "ellekit");
        assert_eq!(report.loaded_backend_count(), 1);
        assert_eq!(report.loaded_image_count(), 1);
        assert_eq!(report.filesystem_only_backend_count(), 0);
        assert_eq!(report.filesystem_path_count(), 0);
        assert_eq!(report.conflict_state(), "external-loaded");
        assert_eq!(
            report.backends[0].loaded_images,
            vec!["/usr/lib/libellekit.dylib".to_string()]
        );
        assert!(report.backends[0].filesystem_paths.is_empty());
        assert_eq!(report.warnings.len(), 1);
    }

    #[test]
    fn detects_filesystem_candidates_without_loaded_images() {
        let report = detect_hook_environment_with(&[], |path| path == "/var/jb/usr/lib/libhooker.dylib");
        assert!(report.active_backend.is_none());
        assert_eq!(report.backends.len(), 1);
        assert_eq!(report.backends[0].id, "libhooker");
        assert_eq!(report.loaded_backend_count(), 0);
        assert_eq!(report.loaded_image_count(), 0);
        assert_eq!(report.filesystem_only_backend_count(), 1);
        assert_eq!(report.filesystem_path_count(), 1);
        assert_eq!(report.conflict_state(), "filesystem-only");
        assert!(report.backends[0].loaded_images.is_empty());
        assert_eq!(
            report.backends[0].filesystem_paths,
            vec!["/var/jb/usr/lib/libhooker.dylib".to_string()]
        );
        assert_eq!(report.warnings.len(), 1);
    }

    #[test]
    fn detects_rootless_ellekit_filesystem_candidates() {
        let report = detect_hook_environment_with(&[], |path| {
            path == "/var/jb/usr/lib/libellekit.dylib"
                || path == "/var/jb/Library/MobileSubstrate/DynamicLibraries/ElleKit.dylib"
        });
        assert!(report.active_backend.is_none());
        assert_eq!(report.backends.len(), 1);
        assert_eq!(report.backends[0].id, "ellekit");
        assert_eq!(
            report.backends[0].filesystem_paths,
            vec![
                "/var/jb/usr/lib/libellekit.dylib".to_string(),
                "/var/jb/Library/MobileSubstrate/DynamicLibraries/ElleKit.dylib".to_string(),
            ]
        );
    }

    #[test]
    fn warns_when_multiple_hook_backends_are_loaded() {
        let images = vec![
            "/usr/lib/libellekit.dylib".to_string(),
            "/usr/lib/libsubstitute.dylib".to_string(),
        ];

        let report = detect_hook_environment_with(&images, |_| false);
        assert_eq!(report.backends.len(), 2);
        assert_eq!(report.loaded_backend_count(), 2);
        assert_eq!(report.conflict_state(), "multiple-loaded");
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("multiple hook ecosystems")));
    }

    #[test]
    fn strategy_is_risky_when_external_backend_is_loaded_under_warn_policy() {
        let report = HookEnvironmentReport {
            active_backend: Some("ellekit".into()),
            backends: vec![super::HookBackendInfo {
                id: "ellekit".into(),
                display_name: "ElleKit".into(),
                loaded_images: vec!["/usr/lib/libellekit.dylib".into()],
                filesystem_paths: Vec::new(),
            }],
            warnings: Vec::new(),
        };

        let decision = resolve_hook_strategy_with_report(&report, HookPolicy::Warn);
        assert!(decision.allowed);
        assert!(decision.inline_hooks_allowed);
        assert!(decision.bootstrap_injection_allowed());
        assert!(decision.query_commands_allowed());
        assert!(decision.hook_install_commands_allowed());
        assert!(decision.hook_status_commands_allowed());
        assert!(decision.hook_stop_commands_allowed());
        assert_eq!(decision.command_mode(), "allowed");
        assert_eq!(decision.strategy, "internal-inline-risky");
        assert_eq!(decision.policy, HookPolicy::Warn);
    }

    #[test]
    fn strategy_allows_query_only_when_external_backend_is_loaded_under_query_only_policy() {
        let report = HookEnvironmentReport {
            active_backend: Some("substrate".into()),
            backends: vec![super::HookBackendInfo {
                id: "substrate".into(),
                display_name: "Cydia Substrate".into(),
                loaded_images: vec!["/usr/lib/libsubstrate.dylib".into()],
                filesystem_paths: Vec::new(),
            }],
            warnings: Vec::new(),
        };

        let decision = resolve_hook_strategy_with_report(&report, HookPolicy::QueryOnlyExternalLoaded);
        assert!(decision.allowed);
        assert!(!decision.inline_hooks_allowed);
        assert!(decision.bootstrap_injection_allowed());
        assert!(decision.query_commands_allowed());
        assert!(!decision.hook_install_commands_allowed());
        assert!(decision.hook_status_commands_allowed());
        assert!(decision.hook_stop_commands_allowed());
        assert_eq!(decision.command_mode(), "query-only");
        assert_eq!(decision.strategy, "query-only-external-loaded");
        assert_eq!(decision.policy, HookPolicy::QueryOnlyExternalLoaded);
    }

    #[test]
    fn strategy_allows_cleanup_only_when_external_backend_is_loaded_under_deny_policy() {
        let report = HookEnvironmentReport {
            active_backend: Some("substrate".into()),
            backends: vec![super::HookBackendInfo {
                id: "substrate".into(),
                display_name: "Cydia Substrate".into(),
                loaded_images: vec!["/usr/lib/libsubstrate.dylib".into()],
                filesystem_paths: Vec::new(),
            }],
            warnings: Vec::new(),
        };

        let decision = resolve_hook_strategy_with_report(&report, HookPolicy::DenyExternalLoaded);
        assert!(!decision.allowed);
        assert!(!decision.inline_hooks_allowed);
        assert!(decision.bootstrap_injection_allowed());
        assert!(!decision.query_commands_allowed());
        assert!(!decision.hook_install_commands_allowed());
        assert!(decision.hook_status_commands_allowed());
        assert!(decision.hook_stop_commands_allowed());
        assert_eq!(decision.command_mode(), "cleanup-only");
        assert_eq!(decision.strategy, "cleanup-only-external-loaded");
        assert_eq!(decision.policy, HookPolicy::DenyExternalLoaded);
    }

    #[test]
    fn recommendations_cover_loaded_backend_and_blocked_policy() {
        let report = HookEnvironmentReport {
            active_backend: Some("ellekit".into()),
            backends: vec![super::HookBackendInfo {
                id: "ellekit".into(),
                display_name: "ElleKit".into(),
                loaded_images: vec!["/usr/lib/libellekit.dylib".into()],
                filesystem_paths: Vec::new(),
            }],
            warnings: Vec::new(),
        };
        let decision = resolve_hook_strategy_with_report(&report, HookPolicy::DenyExternalLoaded);
        let recommendations = hook_environment_recommendations(&report, Some(&decision));
        assert!(recommendations.iter().any(|line| line.contains("cleanup-only mode")));
    }

    #[test]
    fn recommendations_cover_query_only_policy() {
        let report = HookEnvironmentReport {
            active_backend: Some("ellekit".into()),
            backends: vec![super::HookBackendInfo {
                id: "ellekit".into(),
                display_name: "ElleKit".into(),
                loaded_images: vec!["/usr/lib/libellekit.dylib".into()],
                filesystem_paths: Vec::new(),
            }],
            warnings: Vec::new(),
        };
        let decision = resolve_hook_strategy_with_report(&report, HookPolicy::QueryOnlyExternalLoaded);
        let recommendations = hook_environment_recommendations(&report, Some(&decision));
        assert!(recommendations.iter().any(|line| line.contains("inline hooks are disabled")));
    }

    #[test]
    fn recommendations_cover_filesystem_only_backend() {
        let report = HookEnvironmentReport {
            active_backend: None,
            backends: vec![super::HookBackendInfo {
                id: "libhooker".into(),
                display_name: "libhooker".into(),
                loaded_images: Vec::new(),
                filesystem_paths: vec!["/usr/lib/libhooker.dylib".into()],
            }],
            warnings: vec!["hook ecosystem files are present on disk".into()],
        };
        let recommendations = hook_environment_recommendations(&report, None);
        assert!(recommendations
            .iter()
            .any(|line| line.contains("exist on disk but are not loaded")));
    }

    #[test]
    fn recommended_actions_cover_query_only_policy() {
        let report = HookEnvironmentReport {
            active_backend: Some("ellekit".into()),
            backends: vec![super::HookBackendInfo {
                id: "ellekit".into(),
                display_name: "ElleKit".into(),
                loaded_images: vec!["/usr/lib/libellekit.dylib".into()],
                filesystem_paths: Vec::new(),
            }],
            warnings: Vec::new(),
        };
        let decision = resolve_hook_strategy_with_report(&report, HookPolicy::QueryOnlyExternalLoaded);
        let actions = hook_environment_recommended_actions(&report, Some(&decision));

        let query = actions
            .iter()
            .find(|item| item.command_group == "query")
            .expect("query action");
        assert!(query.allowed);
        assert_eq!(query.status, "allowed");
        assert_eq!(query.action_key, "hook.query");
        assert_eq!(query.priority, 1);

        let install = actions
            .iter()
            .find(|item| item.command_group == "hook-install")
            .expect("hook-install action");
        assert!(!install.allowed);
        assert_eq!(install.status, "blocked");
        assert_eq!(install.action_key, "hook.install");
        assert_eq!(install.priority, 4);
        assert!(install.recommendation.contains("query-only mode"));
        assert_eq!(actions[0].command_group, "query");
    }

    #[test]
    fn recommended_actions_cover_cleanup_only_policy() {
        let report = HookEnvironmentReport {
            active_backend: Some("substrate".into()),
            backends: vec![super::HookBackendInfo {
                id: "substrate".into(),
                display_name: "Cydia Substrate".into(),
                loaded_images: vec!["/usr/lib/libsubstrate.dylib".into()],
                filesystem_paths: Vec::new(),
            }],
            warnings: Vec::new(),
        };
        let decision = resolve_hook_strategy_with_report(&report, HookPolicy::DenyExternalLoaded);
        let actions = hook_environment_recommended_actions(&report, Some(&decision));

        let query = actions
            .iter()
            .find(|item| item.command_group == "query")
            .expect("query action");
        assert!(!query.allowed);
        assert_eq!(query.status, "blocked");
        assert_eq!(query.action_key, "hook.query");
        assert_eq!(query.priority, 4);
        assert!(query.recommendation.contains("cleanup-only mode"));

        let stop = actions
            .iter()
            .find(|item| item.command_group == "hook-stop")
            .expect("hook-stop action");
        assert!(stop.allowed);
        assert_eq!(stop.status, "allowed");
        assert_eq!(stop.action_key, "hook.stop");
        assert_eq!(stop.priority, 1);
        assert!(stop.recommendation.contains("cleanup-only mode"));
        assert_eq!(actions[0].command_group, "hook-status");
        assert_eq!(actions[1].command_group, "hook-stop");
    }

    #[test]
    fn coexistence_layer_status_is_not_required_without_external_backend() {
        let report = HookEnvironmentReport {
            active_backend: None,
            backends: vec![],
            warnings: vec![],
        };
        let status = hook_coexistence_layer_status(&report, None);
        assert!(status.available);
        assert_eq!(status.status, "not-required");
    }

    #[test]
    fn coexistence_layer_status_marks_filesystem_only_as_not_required() {
        let report = HookEnvironmentReport {
            active_backend: None,
            backends: vec![super::HookBackendInfo {
                id: "libhooker".into(),
                display_name: "libhooker".into(),
                loaded_images: vec![],
                filesystem_paths: vec!["/var/jb/usr/lib/libhooker.dylib".into()],
            }],
            warnings: vec![],
        };
        let status = hook_coexistence_layer_status(&report, None);
        assert!(status.available);
        assert_eq!(status.status, "not-required-filesystem-only");
    }

    #[test]
    fn coexistence_layer_status_reports_missing_layer_when_external_backend_loaded() {
        let status = hook_coexistence_layer_status_for_mode(Some("cleanup-only"), true, false);
        assert!(!status.available);
        assert_eq!(status.status, "missing-cleanup-only");

        let unknown_status = hook_coexistence_layer_status_for_mode(None, true, false);
        assert!(!unknown_status.available);
        assert_eq!(unknown_status.status, "missing-unknown");
    }
}
