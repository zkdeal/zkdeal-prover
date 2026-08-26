use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

#[test]
fn persistent_jsonl_worker_flushes_each_response() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_differential-batch-v4"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn differential worker");
    let mut stdin = child.stdin.take().expect("worker stdin");
    let stdout = child.stdout.take().expect("worker stdout");
    let (tx, rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut lines = BufReader::new(stdout).lines();
        for _ in 0..2 {
            tx.send(lines.next().transpose()).expect("send worker line");
        }
    });

    for expected_trace in 1..=2 {
        // Malformed requests are sufficient here: the streaming contract is
        // one response per non-empty input line, including validation errors.
        writeln!(stdin, "{{}}").expect("write trace");
        stdin.flush().expect("flush trace");
        let line = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("worker did not flush response before next request")
            .expect("read worker response")
            .expect("worker stdout ended early");
        let response: serde_json::Value = serde_json::from_str(&line).expect("response JSON");
        assert_eq!(response["trace"], expected_trace);
        assert_eq!(response["ok"], false);
        assert!(response["error"].as_str().is_some());
    }

    drop(stdin);
    assert!(child.wait().expect("wait for worker").success());
    reader.join().expect("join reader");
}
