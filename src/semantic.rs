//! L2 — semantic risk typing (s_sem), port of `care/semantic.py` and the
//! class table of `care/common.py`.

use serde::Serialize;

use crate::fixes::Tags;
use crate::py_re;
use crate::pyre::{basename, py_split};

/// L2 risk classes (common.py:13-24).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskClass {
    /// Read-only.
    ReadOnly,
    /// Workspace-scoped write.
    WriteLocal,
    /// Sensitive write / secret touch.
    WriteSensitive,
    /// Network fetch / transfer.
    NetworkFetch,
    /// Shell / interpreter chaining.
    ExecutionChain,
    /// Privilege or permission change.
    PrivilegeOrPermission,
    /// Persistence.
    Persistence,
    /// Destructive.
    Destructive,
    /// Resource abuse.
    ResourceAbuse,
    /// Unmapped head.
    Unknown,
}

impl RiskClass {
    /// `CLASS_BASE_SCORE` (common.py:28-39).
    pub fn base(self) -> f64 {
        match self {
            RiskClass::ReadOnly => 0.00,
            RiskClass::WriteLocal => 0.15,
            RiskClass::WriteSensitive => 0.70,
            RiskClass::NetworkFetch => 0.40,
            RiskClass::ExecutionChain => 0.60,
            RiskClass::PrivilegeOrPermission => 0.75,
            RiskClass::Persistence => 0.80,
            RiskClass::Destructive => 1.00,
            RiskClass::ResourceAbuse => 0.85,
            RiskClass::Unknown => 0.35,
        }
    }

    /// Reference string value.
    pub fn as_str(self) -> &'static str {
        match self {
            RiskClass::ReadOnly => "READ_ONLY",
            RiskClass::WriteLocal => "WRITE_LOCAL",
            RiskClass::WriteSensitive => "WRITE_SENSITIVE",
            RiskClass::NetworkFetch => "NETWORK_FETCH",
            RiskClass::ExecutionChain => "EXECUTION_CHAIN",
            RiskClass::PrivilegeOrPermission => "PRIVILEGE_OR_PERMISSION",
            RiskClass::Persistence => "PERSISTENCE",
            RiskClass::Destructive => "DESTRUCTIVE",
            RiskClass::ResourceAbuse => "RESOURCE_ABUSE",
            RiskClass::Unknown => "UNKNOWN",
        }
    }
}

use RiskClass::*;

const READ_ONLY_HEADS: &[&str] = &[
    "cat",
    "head",
    "tail",
    "less",
    "more",
    "wc",
    "nl",
    "od",
    "hexdump",
    "xxd",
    "strings",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "ag",
    "ack",
    "find",
    "locate",
    "which",
    "whereis",
    "type",
    "command",
    "ls",
    "ll",
    "dir",
    "tree",
    "file",
    "stat",
    "readlink",
    "realpath",
    "pwd",
    "whoami",
    "id",
    "groups",
    "w",
    "who",
    "last",
    "tty",
    "uname",
    "hostname",
    "date",
    "uptime",
    "cal",
    "lsb_release",
    "df",
    "du",
    "free",
    "top",
    "htop",
    "atop",
    "iotop",
    "env",
    "printenv",
    "echo",
    "printf",
    "yes",
    "diff",
    "cmp",
    "comm",
    "sort",
    "uniq",
    "cut",
    "tr",
    "awk",
    "sed",
    "jq",
    "yq",
    "xmllint",
    "column",
    "paste",
    "join",
    "tac",
    "rev",
    "man",
    "help",
    "info",
    "tldr",
    "whatis",
    "md5sum",
    "sha1sum",
    "sha256sum",
    "sha512sum",
    "b2sum",
    "cksum",
    "true",
    "false",
    "test",
    "[",
    "history",
    "bc",
    "dc",
    "seq",
    "expr",
    "sleep",
    "ping",
    "traceroute",
    "mtr",
    "host",
    "dig",
    "nslookup",
    "ps",
    "pgrep",
    "pidof",
    "jobs",
    "pstree",
];
const WRITE_LOCAL_HEADS: &[&str] = &[
    "cp",
    "mv",
    "mkdir",
    "touch",
    "ln",
    "tar",
    "zip",
    "unzip",
    "gzip",
    "gunzip",
    "bzip2",
    "xz",
    "7z",
    "zstd",
    "tee",
    "make",
    "cmake",
    "gradle",
    "mvn",
    "ant",
    "ninja",
    "bazel",
    "pip",
    "pip3",
    "npm",
    "yarn",
    "pnpm",
    "cargo",
    "go",
    "poetry",
    "python",
    "python3",
    "node",
    "ruby",
    "perl",
    "php",
    "lua",
    "git",
    "docker",
    "podman",
    "docker-compose",
    "kubectl",
    "helm",
    "export",
    "alias",
    "unalias",
    "pytest",
    "tox",
    "nose2",
    "rspec",
    "jest",
    "mocha",
    "vitest",
    "gcc",
    "g++",
    "clang",
    "javac",
    "rustc",
    "tsc",
    "vi",
    "vim",
    "nvim",
    "nano",
    "emacs",
];
const NETWORK_FETCH_HEADS: &[&str] = &[
    "curl", "wget", "httpie", "aria2c", "rsync", "scp", "sftp", "ftp", "apt", "apt-get", "yum",
    "dnf", "pacman", "brew", "snap", "flatpak",
    // semantic.py:104-107 lists these under a "WRITE_SENSITIVE (placeholder)"
    // comment but maps them to NETWORK_FETCH; the mapping is kept.
    "nc", "ncat", "netcat", "ssh",
];
const EXECUTION_CHAIN_HEADS: &[&str] = &[
    "bash", "sh", "zsh", "dash", "ksh", "csh", "tcsh", "ash", "exec", "source", ".",
];
const PRIVILEGE_HEADS: &[&str] = &[
    "sudo", "su", "doas", "pkexec", "chmod", "chown", "chgrp", "setcap", "getcap", "visudo",
    "passwd", "chpasswd", "useradd", "userdel", "usermod", "groupadd", "groupdel", "groupmod",
    "newgrp", "adduser", "deluser",
];
const PERSISTENCE_HEADS: &[&str] = &[
    "crontab",
    "at",
    "batch",
    "anacron",
    "systemctl",
    "service",
    "update-rc.d",
    "chkconfig",
    "launchctl",
];
const DESTRUCTIVE_HEADS: &[&str] = &[
    "rm",
    "rmdir",
    "dd",
    "mkfs",
    "mkfs.ext4",
    "mkfs.ext3",
    "mkfs.xfs",
    "mkfs.btrfs",
    "mkfs.vfat",
    "fdisk",
    "parted",
    "gdisk",
    "sgdisk",
    "cfdisk",
    "shred",
    "wipe",
    "wipefs",
    "blkdiscard",
    "truncate",
];
const RESOURCE_ABUSE_HEADS: &[&str] = &[
    "kill",
    "killall",
    "pkill",
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "init",
    "telinit",
    "stress",
    "stress-ng",
    "fallocate",
    "nmap",
    "hping3",
    "masscan",
];

/// `COMMAND_CLASSES` lookup. The Python dict is built in the order above and
/// no head appears in two groups, so group order does not matter.
pub fn lookup(prog: &str) -> RiskClass {
    let groups: [(&[&str], RiskClass); 8] = [
        (READ_ONLY_HEADS, ReadOnly),
        (WRITE_LOCAL_HEADS, WriteLocal),
        (NETWORK_FETCH_HEADS, NetworkFetch),
        (EXECUTION_CHAIN_HEADS, ExecutionChain),
        (PRIVILEGE_HEADS, PrivilegeOrPermission),
        (PERSISTENCE_HEADS, Persistence),
        (DESTRUCTIVE_HEADS, Destructive),
        (RESOURCE_ABUSE_HEADS, ResourceAbuse),
    ];
    groups
        .iter()
        .find(|(heads, _)| heads.contains(&prog))
        .map(|(_, c)| *c)
        .unwrap_or(Unknown)
}

/// `GIT_SUBCOMMAND_CLASSES` (semantic.py:112-127). The reference lists
/// `tag` under both READ_ONLY and WRITE_LOCAL; the later entry wins, so the
/// reference always yields WRITE_LOCAL. FIX-009 resolves the conflict in
/// [`classify_git`].
fn git_sub_class(sub: &str) -> RiskClass {
    const RO: &[&str] = &[
        "status", "log", "diff", "show", "blame", "branch", "remote", "stash", "ls-files",
        "describe", "shortlog", "reflog", "config",
    ];
    // Every other subcommand (the reference's WRITE_LOCAL list: add, commit,
    // checkout, switch, merge, rebase, cherry-pick, am, apply, init, fetch,
    // pull, clone, tag, push, reset, clean) and the `.get` default are
    // WRITE_LOCAL.
    if RO.contains(&sub) {
        ReadOnly
    } else {
        WriteLocal
    }
}

/// One L2 classification.
#[derive(Debug, Clone, Serialize)]
pub struct Classification {
    /// Class.
    pub class: RiskClass,
    /// Score in [0, 1].
    pub score: f64,
    /// Reason string (reference format).
    pub reason: String,
}

fn c(class: RiskClass, score: f64, reason: impl Into<String>) -> Classification {
    Classification {
        class,
        score,
        reason: reason.into(),
    }
}

/// `SemanticClassifier.classify` (semantic.py:133-186).
pub fn classify(atom: &str, tags: &mut Tags) -> Classification {
    let tokens = py_split(atom);
    let Some(first) = tokens.first() else {
        return c(ReadOnly, 0.0, "empty");
    };
    let prog = basename(first);
    if prog == "git" && tokens.len() > 1 {
        return classify_git(&tokens, tags);
    }
    if prog == "rm" {
        return classify_rm(&tokens);
    }
    if prog == "chmod" {
        return classify_chmod(&tokens);
    }
    if prog == "dd" {
        return classify_dd(&tokens);
    }
    if prog == "sed" && tokens.iter().any(|t| t.starts_with("-i")) {
        return c(WriteLocal, WriteLocal.base(), "sed_inplace");
    }
    if prog == "docker" || prog == "podman" {
        return classify_docker(&tokens);
    }
    if matches!(prog, "kill" | "pkill" | "killall") {
        return classify_kill(&tokens);
    }
    let cls = lookup(prog);
    if touches_secret_path(&tokens) && matches!(cls, WriteLocal | ReadOnly) {
        return c(
            WriteSensitive,
            WriteSensitive.base(),
            format!("{prog}:secret_path"),
        );
    }
    if matches!(prog, "rsync" | "scp" | "sftp") && !has_remote_host(&tokens) {
        return c(
            WriteLocal,
            WriteLocal.base(),
            format!("{prog}:local_no_remote_host"),
        );
    }
    c(cls, cls.base(), format!("db_lookup:{prog}"))
}

fn classify_git(tokens: &[&str], tags: &mut Tags) -> Classification {
    let sub = tokens.get(1).copied().unwrap_or("");
    let mut cls = git_sub_class(sub);
    if sub == "push"
        && tokens
            .iter()
            .any(|t| matches!(*t, "-f" | "--force" | "--force-with-lease"))
    {
        return c(Destructive, 0.85, "git_push_force");
    }
    if sub == "reset" && tokens.contains(&"--hard") {
        return c(Destructive, 0.80, "git_reset_hard");
    }
    if sub == "clean"
        && tokens
            .iter()
            .any(|t| t.starts_with("-f") || t.starts_with("-d"))
    {
        return c(Destructive, 0.70, "git_clean_force");
    }
    // FIX-009: `git tag` / `git tag -l|--list …` only list tags.
    if sub == "tag" && (tokens.len() == 2 || tokens.iter().any(|t| matches!(*t, "-l" | "--list"))) {
        cls = ReadOnly;
        tags.fix("FIX-009");
    }
    c(cls, cls.base(), format!("git_{sub}"))
}

fn classify_rm(tokens: &[&str]) -> Classification {
    let flags: Vec<&str> = tokens[1..]
        .iter()
        .copied()
        .filter(|t| t.starts_with('-'))
        .collect();
    let fstr = flags.join(" ");
    let recursive = ["-r", "-R", "--recursive"].iter().any(|x| fstr.contains(x));
    let force = fstr.contains("-f") || fstr.contains("--force");
    let targets: Vec<&str> = tokens[1..]
        .iter()
        .copied()
        .filter(|t| !t.starts_with('-'))
        .collect();
    if (recursive && force) || fstr.contains("-rf") || fstr.contains("-fr") {
        const CRIT: &[&str] = &[
            "/", "/*", "~", "~/*", "/home", "/etc", "/usr", "/var", "/boot", "/bin", "/sbin",
        ];
        for p in &targets {
            if CRIT.contains(p) {
                return c(Destructive, 1.0, format!("rm_rf_critical:{p}"));
            }
        }
        return c(Destructive, 0.9, "rm_rf");
    }
    if recursive {
        return c(Destructive, 0.7, "rm_recursive");
    }
    c(WriteLocal, 0.3, "rm_files")
}

py_re!(re_octal_mode, r"^[0-7]{3,4}$");

fn classify_chmod(tokens: &[&str]) -> Classification {
    for t in &tokens[1..] {
        if t.starts_with('-') {
            continue;
        }
        if re_octal_mode().is_match(t) {
            let mode_str = &t[t.len() - 3..];
            let mode = u32::from_str_radix(mode_str, 8).unwrap_or(0);
            let paths = tokens
                .get(2..)
                .unwrap_or(&[])
                .iter()
                .filter(|p| !p.starts_with('-'));
            let is_sensitive = paths.clone().any(|p| {
                ["/", "~/", "/etc", "/usr", "/bin", "/sbin"]
                    .iter()
                    .any(|s| p.starts_with(s))
            });
            if mode == 0o777 && is_sensitive {
                return c(PrivilegeOrPermission, 0.95, "chmod_777_sensitive");
            }
            if mode == 0o777 {
                return c(PrivilegeOrPermission, 0.80, "chmod_777");
            }
            if t.starts_with('4') || t.starts_with('2') {
                return c(PrivilegeOrPermission, 0.85, format!("chmod_suid:{t}"));
            }
        }
        if t.contains("+s") {
            return c(PrivilegeOrPermission, 0.85, "chmod_setuid_sym");
        }
        break;
    }
    c(PrivilegeOrPermission, 0.35, "chmod_normal")
}

py_re!(re_dd_block, r"of=/dev/(sd|hd|nvme|vd|md|mmcblk|loop)");
py_re!(re_dd_null, r"of=/dev/(zero|null)");

fn classify_dd(tokens: &[&str]) -> Classification {
    let joined = tokens.join(" ");
    if re_dd_block().is_match(&joined) {
        return c(Destructive, 1.0, "dd_block_device");
    }
    if re_dd_null().is_match(&joined) {
        return c(ReadOnly, 0.1, "dd_to_null");
    }
    c(Destructive, 0.6, "dd_generic")
}

fn classify_docker(tokens: &[&str]) -> Classification {
    if tokens.contains(&"run") && tokens.contains(&"--privileged") {
        return c(PrivilegeOrPermission, 0.90, "docker_privileged");
    }
    if ["ps", "images", "logs", "inspect"]
        .iter()
        .any(|t| tokens.contains(t))
    {
        return c(ReadOnly, 0.0, "docker_read");
    }
    c(WriteLocal, WriteLocal.base(), "docker_other")
}

py_re!(re_kill_init, r"\bkill\s+-9?\s+(-?1|\$\$)\b");
py_re!(re_killall_crit, r"\bkillall\s+(sshd|init|systemd|dbus)\b");
py_re!(re_pkill_root, r"\bpkill\s+-9\s+-u\s+root\b");

fn classify_kill(tokens: &[&str]) -> Classification {
    let joined = tokens.join(" ");
    if re_kill_init().is_match(&joined) {
        return c(ResourceAbuse, 0.95, "kill_init");
    }
    if re_killall_crit().is_match(&joined) {
        return c(ResourceAbuse, 0.90, "killall_critical");
    }
    if re_pkill_root().is_match(&joined) {
        return c(ResourceAbuse, 0.90, "pkill_root");
    }
    c(ResourceAbuse, ResourceAbuse.base(), "kill_generic")
}

fn touches_secret_path(tokens: &[&str]) -> bool {
    const SECRET: &[&str] = &[
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "~/.ssh/id_",
        "~/.ssh/authorized_keys",
        "~/.aws/credentials",
        "~/.docker/config.json",
        "~/.kube/config",
        "~/.gnupg/",
        "~/.netrc",
        "/root/.ssh",
        ".bash_history",
        ".zsh_history",
        ".mysql_history",
    ];
    let joined = if tokens.len() > 1 {
        tokens[1..].join(" ")
    } else {
        String::new()
    };
    SECRET.iter().any(|s| joined.contains(s))
}

py_re!(re_remote_host, r"\b[\w.-]+@[\w.-]+:");

fn has_remote_host(tokens: &[&str]) -> bool {
    let joined = if tokens.len() > 1 {
        tokens[1..].join(" ")
    } else {
        String::new()
    };
    re_remote_host().is_match(&joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cl(a: &str) -> (RiskClass, f64, String) {
        let r = classify(a, &mut Tags::default());
        (r.class, r.score, r.reason)
    }

    #[test]
    fn reference_examples() {
        assert_eq!(
            cl("rm -rf node_modules"),
            (Destructive, 0.9, "rm_rf".into())
        );
        assert_eq!(
            cl("rm -rf /"),
            (Destructive, 1.0, "rm_rf_critical:/".into())
        );
        assert_eq!(
            cl("git push --force"),
            (Destructive, 0.85, "git_push_force".into())
        );
        assert_eq!(cl("sudo apt-get install jq").0, PrivilegeOrPermission);
        assert_eq!(cl("rsync -avz ./data user@host:/backup/").0, NetworkFetch);
        assert_eq!(cl("rsync -a a b").0, WriteLocal);
        assert_eq!(cl("cat ~/.ssh/id_rsa").0, WriteSensitive);
        assert_eq!(cl("chmod 777 /etc/passwd").1, 0.95);
        assert_eq!(cl("chmod u+s x").2, "chmod_setuid_sym");
        assert_eq!(cl("kill -9 1").2, "kill_init");
        assert_eq!(cl("dd if=/dev/zero of=/dev/sda").2, "dd_block_device");
        assert_eq!(cl("/usr/bin/python3 x.py").2, "db_lookup:python3");
        assert_eq!(cl("npx foo").0, Unknown);
    }

    #[test]
    fn git_tag_listing_fix_009() {
        let mut t = Tags::default();
        assert_eq!(classify("git tag", &mut t).class, ReadOnly);
        assert!(t.fixes.contains("FIX-009"));
        assert_eq!(cl("git tag -l 'v*'").0, ReadOnly);
        assert_eq!(cl("git tag v1.0").0, WriteLocal);
    }
}
