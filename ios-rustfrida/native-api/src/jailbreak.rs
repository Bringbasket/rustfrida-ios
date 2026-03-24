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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookPolicy {
    Warn,
    DenyExternalLoaded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookStrategyDecision {
    pub policy: HookPolicy,
    pub strategy: String,
    pub allowed: bool,
    pub reason: Option<String>,
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
            HookPolicy::DenyExternalLoaded => "deny-external-loaded",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "warn" => Some(HookPolicy::Warn),
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
                reason: Some(
                    "external hook backend is already loaded; ios-rustfrida will still use its internal inline hook engine, but coexistence is not implemented".into(),
                ),
            },
            HookPolicy::DenyExternalLoaded => HookStrategyDecision {
                policy,
                strategy: "blocked-external-loaded".into(),
                allowed: false,
                reason: Some(
                    "external hook backend is already loaded and current policy denies installing ios-rustfrida inline hooks in this state".into(),
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
        if !decision.allowed {
            recommendations.push(
                "current hook policy blocks inline hooks in this process; use query-only commands or explicitly relax IOS_RUSTFRIDA_HOOK_POLICY if you accept coexistence risk".into(),
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

#[cfg(test)]
mod tests {
    use super::{
        detect_hook_environment_with, hook_environment_recommendations, resolve_hook_strategy_with_report,
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
        assert_eq!(decision.strategy, "internal-inline-risky");
        assert_eq!(decision.policy, HookPolicy::Warn);
    }

    #[test]
    fn strategy_blocks_when_external_backend_is_loaded_under_deny_policy() {
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
        assert_eq!(decision.strategy, "blocked-external-loaded");
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
        assert!(recommendations.iter().any(|line| line.contains("query-only commands")));
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
}
