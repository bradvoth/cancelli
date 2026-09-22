//! Every FIX-/EXT- id in the registry must be documented in README.md and in
//! docs/COMMIT_MSG.txt, and vice versa. Keeps the tables from drifting.

use cancelli::fixes::REGISTRY;

fn ids_in(text: &str) -> std::collections::BTreeSet<String> {
    let re = regex::Regex::new(r"(?:FIX|EXT)-\d{3}").unwrap();
    re.find_iter(text).map(|m| m.as_str().to_string()).collect()
}

#[test]
fn readme_and_commit_msg_cover_every_id() {
    let registry: std::collections::BTreeSet<String> =
        REGISTRY.iter().map(|e| e.id.to_string()).collect();
    let readme = include_str!("../README.md");
    let commit = include_str!("../docs/COMMIT_MSG.txt");
    for (name, text) in [("README.md", readme), ("docs/COMMIT_MSG.txt", commit)] {
        let found = ids_in(text);
        let missing: Vec<&String> = registry.difference(&found).collect();
        let extra: Vec<&String> = found.difference(&registry).collect();
        assert!(missing.is_empty(), "{name} is missing ids: {missing:?}");
        assert!(extra.is_empty(), "{name} has unknown ids: {extra:?}");
    }
}
