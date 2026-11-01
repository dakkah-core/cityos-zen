use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

// Exercise the real launcher and Python startup, not a replacement checker.
#[test]
fn checker_ignores_caller_pythonpath_startup_code() -> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("cityos-zen-python-{}-{nonce}", std::process::id()));
    fs::create_dir(&dir)?;
    let site = dir.join("sitecustomize.py");
    let baseline_marker = dir.join("baseline");
    let launcher_marker = dir.join("launcher");
    fs::write(
        &site,
        "import os\nfrom pathlib import Path\nPath(os.environ['CITYOS_ZEN_PYTHON_MARKER']).write_text('executed')\n",
    )?;

    // Verify that the fixture really would run with ordinary Python startup.
    let python = if cfg!(windows) { "python" } else { "python3" };
    let baseline = Command::new(python)
        .args(["-c", "pass"])
        .env("PYTHONPATH", &dir)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env_remove("PYTHONHOME")
        .env_remove("PYTHONNOUSERSITE")
        .env_remove("PYTHONSAFEPATH")
        .env_remove("PYTHONINSPECT")
        .env("CITYOS_ZEN_PYTHON_MARKER", &baseline_marker)
        .output()?;
    assert!(baseline.status.success());
    assert!(baseline_marker.exists(), "Python startup fixture did not run");

    let result = Command::new(env!("CARGO_BIN_EXE_cityos-zen-xtask"))
        .arg("--help")
        .env("PYTHONPATH", &dir)
        .env("CITYOS_ZEN_PYTHON_MARKER", &launcher_marker)
        .output()?;
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("previously trusted"));
    assert!(!launcher_marker.exists(), "caller startup code ran inside the checker");

    fs::remove_file(site)?;
    fs::remove_file(baseline_marker)?;
    fs::remove_dir(dir)?;
    Ok(())
}
