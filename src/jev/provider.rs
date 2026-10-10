//! Judge providers (D28): which service answers `POST {base_url}{path}`.
//!
//! * `typesafe` — TypeSafe's hosted API, the default; every value is what
//!   it was before D28.
//! * `openrouter` — OpenRouter's Decisions API, which hosts the same Jev
//!   model as `typesafe/jev-1.13` and reports it under a dated snapshot
//!   slug (`typesafe/jev-1.13-20260917` on 2026-10-09), hence the
//!   `typesafe/jev-1.13-*` expected-model default ([`super::model_matches`]).
//!
//! A provider only supplies **defaults** for the transport keys
//! (`base_url`, `path`, `model`, `expected_model`, `api_key_env`) and the
//! name of the base-URL override variable. Any `[judge]` key set in the
//! file still wins. The provider itself comes from the file alone: an
//! exported key never selects it, so an existing setup cannot change
//! because of the environment.

use serde::Serialize;

use super::client::DEFAULT_EXPECTED_MODEL;

/// Who serves the judge requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    /// `api.typesafe.ai`, `/v1/systemone`.
    #[default]
    TypeSafe,
    /// `openrouter.ai`, `/api/alpha/decisions`.
    OpenRouter,
}

/// A provider's defaults for the transport keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderDefaults {
    /// `judge.base_url`.
    pub base_url: &'static str,
    /// `judge.path`, appended to the base URL.
    pub path: &'static str,
    /// `judge.model`, sent in the request body.
    pub model: &'static str,
    /// `judge.expected_model`, what `response.model` must report (D23).
    pub expected_model: &'static str,
    /// `judge.api_key_env`.
    pub api_key_env: &'static str,
    /// Environment variable that overrides `judge.base_url`.
    pub base_url_env: &'static str,
}

/// TypeSafe's hosted API.
pub const TYPESAFE: ProviderDefaults = ProviderDefaults {
    base_url: "https://api.typesafe.ai",
    path: "/v1/systemone",
    model: DEFAULT_EXPECTED_MODEL,
    expected_model: DEFAULT_EXPECTED_MODEL,
    api_key_env: "TYPESAFE_API_KEY",
    base_url_env: "TYPESAFE_BASE_URL",
};

/// OpenRouter's Decisions API (`https://openrouter.ai/typesafe/jev-1.13`).
pub const OPENROUTER: ProviderDefaults = ProviderDefaults {
    base_url: "https://openrouter.ai",
    path: "/api/alpha/decisions",
    model: "typesafe/jev-1.13",
    expected_model: "typesafe/jev-1.13-*",
    api_key_env: "OPENROUTER_API_KEY",
    base_url_env: "OPENROUTER_BASE_URL",
};

impl Provider {
    /// Every provider, in documentation order.
    pub const ALL: [Provider; 2] = [Provider::TypeSafe, Provider::OpenRouter];

    /// The config-file name.
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::TypeSafe => "typesafe",
            Provider::OpenRouter => "openrouter",
        }
    }

    /// Parse a config-file name.
    pub fn parse(s: &str) -> Option<Provider> {
        Provider::ALL.into_iter().find(|p| p.as_str() == s)
    }

    /// The transport defaults.
    pub fn defaults(self) -> &'static ProviderDefaults {
        match self {
            Provider::TypeSafe => &TYPESAFE,
            Provider::OpenRouter => &OPENROUTER,
        }
    }
}

/// Names accepted by `judge.provider`, for diagnostics.
pub fn names() -> String {
    Provider::ALL
        .iter()
        .map(|p| p.as_str())
        .collect::<Vec<_>>()
        .join("|")
}

/// D28: is `name` Jev, under either provider? `name` is taken literally
/// and must be a name a provider's default `expected_model` accepts: a
/// reported `response.model` (`jev-1.13.0`, `typesafe/jev-1.13-20260917`),
/// the two defaults themselves (so a `judge.expected_model` left at, or set
/// to, a default is tested the same way), or a narrower pattern under
/// OpenRouter's prefix (`typesafe/jev-1.13-2026*`). A wider pattern
/// (`typesafe/jev-1.13*`, `jev-1.13.*`) is not Jev: it would accept names
/// the defaults refuse, and the calibration warning (`tunables`) then says
/// so. The one answer to "is this backend Jev?": `cancelli calibrate`
/// refuses to fit Jev against itself and accepts references from either
/// provider, the "calibrated on Jev" warning stays quiet, a rubric
/// declaring Jev is accepted, and `cancelli eval` reuses logged answers
/// across the two providers.
pub fn is_jev(name: &str) -> bool {
    Provider::ALL
        .iter()
        .map(|p| p.defaults().expected_model)
        .any(|e| name == e || super::model_matches(e, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for p in Provider::ALL {
            assert_eq!(Provider::parse(p.as_str()), Some(p));
        }
        assert_eq!(Provider::parse("TypeSafe"), None);
        assert_eq!(Provider::parse(""), None);
        assert_eq!(names(), "typesafe|openrouter");
        assert_eq!(Provider::default(), Provider::TypeSafe);
    }

    #[test]
    fn typesafe_defaults_are_the_pre_d28_values() {
        let d = Provider::TypeSafe.defaults();
        assert_eq!(d.base_url, "https://api.typesafe.ai");
        assert_eq!(d.path, "/v1/systemone");
        assert_eq!(d.model, "jev-1.13.0");
        assert_eq!(d.expected_model, "jev-1.13.0");
        assert_eq!(d.api_key_env, "TYPESAFE_API_KEY");
        assert_eq!(d.base_url_env, "TYPESAFE_BASE_URL");
    }

    #[test]
    fn openrouter_defaults() {
        let d = Provider::OpenRouter.defaults();
        assert_eq!(d.base_url, "https://openrouter.ai");
        assert_eq!(d.path, "/api/alpha/decisions");
        assert_eq!(d.model, "typesafe/jev-1.13");
        assert_eq!(d.expected_model, "typesafe/jev-1.13-*");
        assert_eq!(d.api_key_env, "OPENROUTER_API_KEY");
        assert_eq!(d.base_url_env, "OPENROUTER_BASE_URL");
    }

    #[test]
    fn is_jev_accepts_both_providers_names_and_nothing_else() {
        for jev in [
            "jev-1.13.0",
            "typesafe/jev-1.13-20260917",
            "typesafe/jev-1.13-20991231",
            "typesafe/jev-1.13-*",
            // a narrower pattern under OpenRouter's prefix
            "typesafe/jev-1.13-2026*",
        ] {
            assert!(is_jev(jev), "{jev}");
        }
        for other in [
            "",
            "jev-1.13.1",
            "jev-1.13.0-rc1",
            "typesafe/jev-1.13",
            "typesafe/jev-1.14-20260917",
            "qwen-local",
            "*",
            // wider patterns: they would accept names the defaults refuse
            "typesafe/jev-1.13*",
            "typesafe/jev-*",
            "jev-1.13.*",
            "jev-1.13.0*",
        ] {
            assert!(!is_jev(other), "{other}");
        }
    }
}
