//! D20: `Tunables::default()` must equal the built-in behaviour. Its
//! canonical serialization is pinned by a committed snapshot
//! (tests/golden/tunables_default.json), so any drift of a default fails
//! here. After an intentional change, regenerate with
//! `CANCELLI_UPDATE_GOLDEN=1 cargo test --test tunables_golden` and review
//! the diff.

use cancelli::tunables::Tunables;

const GOLDEN: &str = "tests/golden/tunables_default.json";

#[test]
fn default_tunables_match_the_golden_snapshot() {
    let t = Tunables::default();
    let text = serde_json::to_string_pretty(&serde_json::json!({
        "config_fingerprint": t.fingerprint(),
        "tunables": t.canonical(),
    }))
    .unwrap()
        + "\n";
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN);
    if std::env::var_os("CANCELLI_UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, &text).unwrap();
    }
    let golden = std::fs::read_to_string(&path).expect("golden snapshot");
    assert_eq!(
        text, golden,
        "Tunables::default() drifted from {GOLDEN}; defaults must equal current behaviour (D20)"
    );
    assert!(t.overrides().is_empty());
}

/// README "Tuning" documents every tunable key with its default.
#[test]
fn readme_tunable_table_lists_every_key_with_its_default() {
    let readme = include_str!("../README.md");
    let canon = Tunables::default().canonical();
    for k in cancelli::tunables::KNOBS {
        let row = readme
            .lines()
            .find(|l| l.starts_with(&format!("| `{}` |", k.key)))
            .unwrap_or_else(|| panic!("README has no row for {}", k.key));
        if k.key != "jev.rubric_file" {
            let v = cancelli::tunables::toml_value(&canon[k.key]);
            assert!(row.contains(&format!("| `{v}` |")), "{}: {row}", k.key);
        }
        assert!(row.contains(k.source), "{}: provenance", k.key);
    }
}
