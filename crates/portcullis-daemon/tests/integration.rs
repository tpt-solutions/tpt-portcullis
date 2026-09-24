//! Integration tests: config file → parse → verify → netctl apply (mock/in-memory).

use std::io::Write;
use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;

use portcullis_daemon::config::load_ruleset;
use portcullis_daemon::control::{send_request, Request, Response};
use portcullis_daemon::state::DaemonState;

const VALID_TOML: &str = r#"
[ruleset]
version = 1

[[ruleset.chains]]
name = "input"
default_policy = "drop"

[[ruleset.chains.rules]]
id = 1
priority = 10
description = "allow ssh"
action = "accept"

[ruleset.chains.rules.matcher]
protocol = "tcp"
dst_port = { single = 22 }
src_addr = "any"
dst_addr = "any"
src_port = "any"
in_interface = "any"
out_interface = "any"

[[ruleset.chains.rules]]
id = 2
priority = 20
description = "drop the rest"
action = "drop"

[ruleset.chains.rules.matcher]
protocol = "any"
dst_port = "any"
src_addr = "any"
dst_addr = "any"
src_port = "any"
in_interface = "any"
out_interface = "any"
"#;

const LINT_FAILING_TOML: &str = r#"
[ruleset]
version = 1

[[ruleset.chains]]
name = "input"
default_policy = "drop"

[[ruleset.chains.rules]]
id = 1
priority = 10
action = "accept"

[ruleset.chains.rules.matcher]
protocol = "tcp"
dst_port = { range = { start = 0, end = 65535 } }

[[ruleset.chains.rules]]
id = 2
priority = 20
action = "drop"

[ruleset.chains.rules.matcher]
protocol = "tcp"
dst_port = { single = 22 }
"#;

fn write_temp(name: &str, contents: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("portcullis-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    path
}

#[test]
fn config_file_parses_and_verifies() {
    let path = write_temp("valid.toml", VALID_TOML);
    let rs = load_ruleset(&path).expect("valid config should verify");
    assert_eq!(rs.version, 1);
    assert_eq!(rs.chains.len(), 1);
    assert_eq!(rs.iter_rules().count(), 2);
}

#[test]
fn config_file_with_lint_failure_is_rejected() {
    let path = write_temp("lint-fail.toml", LINT_FAILING_TOML);
    let err = load_ruleset(&path).expect_err("unreachable rule should fail verify");
    let msg = err.to_string();
    assert!(
        msg.contains("verification"),
        "error should mention verification: {msg}"
    );
    assert!(
        msg.contains("unreachable") || msg.contains("rule"),
        "should point at the issue: {msg}"
    );
}

#[test]
fn missing_config_file_errors() {
    let path = PathBuf::from("/nonexistent/portcullis/config.toml");
    assert!(load_ruleset(&path).is_err());
}

#[test]
fn apply_through_netctl_backend_in_memory() {
    let path = write_temp("apply.toml", VALID_TOML);
    let rs = load_ruleset(&path).unwrap();

    let state = DaemonState::new(PathBuf::from("unused.toml")).expect("backend connect");
    let outcome = state.apply(&rs).expect("apply should succeed in-memory");
    assert_eq!(outcome.version, 1);
    assert_eq!(outcome.rules, 2);
    assert!(
        outcome.planned_changes >= 2,
        "expected adds, got {}",
        outcome.planned_changes
    );

    // State is held.
    assert!(state.current_ruleset().is_some());
    assert_eq!(state.last_apply().map(|a| a.rules), Some(2));
}

#[test]
fn control_socket_round_trip() {
    // Bind an ephemeral listener and serve one connection using the same
    // dispatch path the daemon uses — here we exercise send_request against
    // a minimal inline server that mirrors control protocol.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        handle_one(stream);
    });

    let resp = send_request(&addr.to_string(), &Request::Status).expect("client call");
    server.join().unwrap();
    assert!(resp.ok);
    assert!(resp.status.is_some());
}

fn handle_one(stream: TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let req: Request = serde_json::from_str(line.trim()).unwrap();
    let resp = match req {
        Request::Status => Response {
            ok: true,
            error: None,
            applied: None,
            status: Some(portcullis_daemon::control::StatusPayload {
                config_path: "test".into(),
                loaded: false,
                version: None,
                chains: None,
                rules: None,
                last_apply: None,
            }),
            message: None,
        },
        _ => Response {
            ok: false,
            error: Some("unexpected".into()),
            applied: None,
            status: None,
            message: None,
        },
    };
    let mut out = serde_json::to_string(&resp).unwrap();
    out.push('\n');
    let mut w = stream;
    std::io::Write::write_all(&mut w, out.as_bytes()).unwrap();
    std::io::Write::flush(&mut w).unwrap();
}
