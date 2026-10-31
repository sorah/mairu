//! Tool labels such as `ai-agent`: what a request's ancestry, environment names and session marks say about the
//! tool behind it. Every signal only adds a label, and all of them can be evaded or forged by same-user code, so
//! labels are a guardrail for policies, never a boundary.

/// The built-in label.
pub const AI_AGENT: &str = "ai-agent";

const AI_AGENT_PROCESS_NAMES: &[&str] = &[
    "claude",
    "codex",
    "gemini",
    "cursor-agent",
    "aider",
    "opencode",
    "goose",
    "amp",
    "crush",
    "qwen",
    "copilot",
];

const AI_AGENT_ENV_NAMES: &[&str] = &[
    "AI_AGENT",
    "CLAUDECODE",
    "GEMINI_CLI",
    "CODEX_SANDBOX",
    "CODEX_THREAD_ID",
    "CURSOR_AGENT",
    "QWEN_CODE",
    "OPENCODE",
    "GOOSE_TERMINAL",
    "AMP_CURRENT_THREAD_ID",
    "COPILOT_CLI",
    "CRUSH",
];

/// A label and the signals that attach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolLabel {
    /// `[a-z0-9-]+`
    pub name: String,
    pub process_names: Vec<String>,
    pub env_names: Vec<String>,
}

impl ToolLabel {
    /// The labels the agent detects: `ai-agent` only.
    pub fn builtin() -> Vec<Self> {
        vec![Self {
            name: AI_AGENT.to_owned(),
            process_names: AI_AGENT_PROCESS_NAMES
                .iter()
                .map(|&s| s.to_owned())
                .collect(),
            env_names: AI_AGENT_ENV_NAMES.iter().map(|&s| s.to_owned()).collect(),
        }]
    }

    pub fn is_valid_name(name: &str) -> bool {
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    }
}

/// The labels of a request and what matched, such as `process:claude`, `env:CLAUDECODE` or `mark:ai-agent`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Detection {
    pub tools: std::collections::BTreeSet<String>,
    pub tool_matches: std::collections::BTreeSet<String>,
}

impl Detection {
    /// Matches each process's `comm`, `exe` basename, and `argv[0]` and `argv[1]` basenames, the environment names,
    /// and the marks of every session in the ancestry, exactly.
    pub fn detect(
        ancestry: &[crate::platform::Ancestor],
        env_names: &[String],
        marks: &Marks,
        labels: &[ToolLabel],
    ) -> Self {
        let mut detection = Self::default();
        for ancestor in ancestry {
            for name in process_names(ancestor) {
                for label in labels.iter().filter(|l| l.process_names.contains(&name)) {
                    detection.add(&label.name, format!("process:{name}"));
                }
            }
            if let Some(session) = &ancestor.session {
                for label in marks.get(session) {
                    detection.add(label, format!("mark:{label}"));
                }
            }
        }
        for name in env_names {
            for label in labels.iter().filter(|l| l.env_names.contains(name)) {
                detection.add(&label.name, format!("env:{name}"));
            }
        }
        detection
    }

    fn add(&mut self, label: &str, matched: String) {
        self.tools.insert(label.to_owned());
        self.tool_matches.insert(matched);
    }

    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// `ai-agent (process:claude, env:CLAUDECODE)`, for the terminal and prompt details.
    pub fn summary(&self) -> String {
        let tools = self.tools.iter().cloned().collect::<Vec<_>>().join(", ");
        if self.tool_matches.is_empty() {
            return tools;
        }
        let matches = self
            .tool_matches
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        format!("{tools} ({matches})")
    }

    /// What this process looks like to the agent, apart from session marks: for the terminal, where the agent's own
    /// detection is not known yet.
    pub fn of_current_process() -> Self {
        let uid = nix::unistd::geteuid().as_raw();
        let ancestry = crate::platform::process().ancestry(std::process::id(), 0, uid);
        Self::detect(
            &ancestry,
            &env_names(),
            &Marks::default(),
            &ToolLabel::builtin(),
        )
    }
}

fn process_names(ancestor: &crate::platform::Ancestor) -> Vec<String> {
    use std::os::unix::ffi::OsStrExt;
    let basename = |p: &std::ffi::OsStr| {
        let bytes = p.as_bytes();
        let name = bytes.rsplit(|b| *b == b'/').next().unwrap_or(bytes);
        String::from_utf8_lossy(name).into_owned()
    };
    let mut names: Vec<String> = ancestor.comm.iter().cloned().collect();
    names.extend(ancestor.exe.iter().map(|e| basename(e.as_os_str())));
    names.extend(ancestor.argv.iter().take(2).map(|a| basename(a)));
    names.retain(|n| !n.is_empty());
    names.dedup();
    names
}

/// The names of this process's environment variables, never their values, as `ClientContext.env_names`.
pub fn env_names() -> Vec<String> {
    let mut names: Vec<String> = std::env::vars_os()
        .filter_map(|(k, _)| k.into_string().ok())
        .collect();
    names.sort();
    names
}

/// Labels a human attached to terminal sessions with `mairu lock --tool`; in memory only.
#[derive(Debug, Default)]
pub struct Marks {
    // Keyed by `SessionIdentity::Tty`, so a reused session id never matches.
    by_session: std::collections::HashMap<
        crate::platform::SessionIdentity,
        std::collections::BTreeSet<String>,
    >,
}

impl Marks {
    pub fn add(&mut self, session: crate::platform::SessionIdentity, labels: &[String]) {
        self.by_session
            .entry(session)
            .or_default()
            .extend(labels.iter().cloned());
    }

    /// Returns the labels still marked.
    pub fn remove(
        &mut self,
        session: &crate::platform::SessionIdentity,
        labels: &[String],
    ) -> Vec<String> {
        let Some(marked) = self.by_session.get_mut(session) else {
            return vec![];
        };
        for label in labels {
            marked.remove(label);
        }
        let remaining = marked.iter().cloned().collect();
        if marked.is_empty() {
            self.by_session.remove(session);
        }
        remaining
    }

    pub fn get(&self, session: &crate::platform::SessionIdentity) -> impl Iterator<Item = &String> {
        self.by_session.get(session).into_iter().flatten()
    }

    /// Drops the marks of sessions that ended.
    pub fn sweep(&mut self, alive: impl Fn(&crate::platform::SessionIdentity) -> bool) {
        self.by_session.retain(|s, _| alive(s));
    }

    pub fn len(&self) -> usize {
        self.by_session.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_session.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PANE: crate::platform::SessionIdentity = crate::platform::SessionIdentity::Tty {
        sid: 4242,
        leader_start_time: 7,
    };

    fn ancestor(comm: &str, exe: Option<&str>, argv: &[&str]) -> crate::platform::Ancestor {
        crate::platform::Ancestor {
            pid: 100,
            comm: Some(comm.to_owned()),
            exe: exe.map(Into::into),
            argv: argv.iter().map(Into::into).collect(),
            session: None,
        }
    }

    fn detect(ancestry: &[crate::platform::Ancestor], env: &[&str], marks: &Marks) -> Detection {
        let env: Vec<String> = env.iter().map(|&s| s.to_owned()).collect();
        Detection::detect(ancestry, &env, marks, &ToolLabel::builtin())
    }

    fn set(items: &[&str]) -> std::collections::BTreeSet<String> {
        items.iter().map(|&s| s.to_owned()).collect()
    }

    #[test]
    fn test_process_names() {
        let marks = Marks::default();
        let mairu = ancestor("mairu", Some("/usr/bin/mairu"), &["mairu", "exec"]);
        // comm
        let d = detect(&[mairu.clone(), ancestor("claude", None, &[])], &[], &marks);
        assert_eq!(d.tools, set(&["ai-agent"]));
        assert_eq!(d.tool_matches, set(&["process:claude"]));
        // exe basename
        let d = detect(
            &[ancestor("MainThread", Some("/opt/codex/bin/codex"), &[])],
            &[],
            &marks,
        );
        assert_eq!(d.tool_matches, set(&["process:codex"]));
        // argv[0] basename
        let d = detect(
            &[ancestor("node", None, &["/home/u/.local/bin/gemini"])],
            &[],
            &marks,
        );
        assert_eq!(d.tool_matches, set(&["process:gemini"]));
        // argv[1] basename, as for interpreters
        let d = detect(
            &[ancestor(
                "node",
                Some("/usr/bin/node"),
                &["node", "/usr/lib/node_modules/.bin/opencode"],
            )],
            &[],
            &marks,
        );
        assert_eq!(d.tool_matches, set(&["process:opencode"]));
        // Exact matches only.
        let d = detect(
            &[ancestor("claude-helper", None, &["claude.sh", "--claude"])],
            &[],
            &marks,
        );
        assert!(d.is_empty());
        assert!(detect(&[mairu], &[], &marks).is_empty());
    }

    #[test]
    fn test_env_names() {
        let marks = Marks::default();
        let d = detect(&[], &["HOME", "CLAUDECODE", "AI_AGENT"], &marks);
        assert_eq!(d.tools, set(&["ai-agent"]));
        assert_eq!(d.tool_matches, set(&["env:AI_AGENT", "env:CLAUDECODE"]));
        assert!(detect(&[], &["CLAUDECODE_X", "claudecode"], &marks).is_empty());
    }

    #[test]
    fn test_env_names_are_keys_only() {
        let mut keys: Vec<String> = std::env::vars_os()
            .filter_map(|(k, _)| k.into_string().ok())
            .collect();
        keys.sort();
        assert_eq!(env_names(), keys);
    }

    #[test]
    fn test_marks() {
        let mut marks = Marks::default();
        marks.add(PANE, &[AI_AGENT.to_owned(), "ci".to_owned()]);
        // A setsid child with no tty, whose ancestry passes through the marked pane.
        let mut shell = ancestor("zsh", None, &["-zsh"]);
        shell.session = Some(PANE);
        let child = ancestor("aws", None, &["aws", "s3", "ls"]);
        let d = detect(&[child.clone(), shell], &[], &marks);
        assert_eq!(d.tools, set(&["ai-agent", "ci"]));
        assert_eq!(d.tool_matches, set(&["mark:ai-agent", "mark:ci"]));
        // Another pane, and a new session that reuses the session id.
        let mut other = ancestor("zsh", None, &["-zsh"]);
        other.session = Some(crate::platform::SessionIdentity::Tty {
            sid: 5000,
            leader_start_time: 7,
        });
        assert!(detect(&[child.clone(), other], &[], &marks).is_empty());
        let mut reused = ancestor("zsh", None, &["-zsh"]);
        reused.session = Some(crate::platform::SessionIdentity::Tty {
            sid: 4242,
            leader_start_time: 8,
        });
        assert!(detect(&[child, reused], &[], &marks).is_empty());

        assert_eq!(marks.remove(&PANE, &["ci".to_owned()]), vec![AI_AGENT]);
        assert!(marks.remove(&PANE, &[AI_AGENT.to_owned()]).is_empty());
        assert!(marks.is_empty());
    }

    #[test]
    fn test_marks_sweep() {
        let mut marks = Marks::default();
        marks.add(PANE, &[AI_AGENT.to_owned()]);
        marks.sweep(|_| true);
        assert_eq!(marks.len(), 1);
        marks.sweep(|_| false);
        assert!(marks.is_empty());
    }

    #[test]
    fn test_label_names() {
        assert!(ToolLabel::is_valid_name("ai-agent"));
        assert!(ToolLabel::is_valid_name("ci2"));
        assert!(!ToolLabel::is_valid_name(""));
        assert!(!ToolLabel::is_valid_name("AI"));
        assert!(!ToolLabel::is_valid_name("a b"));
        assert!(!ToolLabel::is_valid_name("a_b"));
    }

    #[test]
    fn test_summary() {
        let d = detect(
            &[ancestor("claude", None, &[])],
            &["CLAUDECODE"],
            &Marks::default(),
        );
        assert_eq!(d.summary(), "ai-agent (env:CLAUDECODE, process:claude)");
    }
}
