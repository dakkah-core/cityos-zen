//! A fresh network namespace is only one part of preview isolation.
//! Existing sockets and filesystem Unix sockets are not isolated by unshare.
use cityos_zen_contracts::PolicyError;
use nix::sched::{unshare, CloneFlags};
use std::path::PathBuf;

fn isolate_with(
    mut namespace: impl FnMut() -> Result<PathBuf, ()>,
    enter: impl FnOnce() -> Result<(), ()>,
) -> Result<(), PolicyError> {
    let before = namespace().map_err(|_| PolicyError::Evaluation)?;
    enter().map_err(|_| PolicyError::Evaluation)?;
    let after = namespace().map_err(|_| PolicyError::Evaluation)?;
    if before == after {
        return Err(PolicyError::Evaluation);
    }
    Ok(())
}

pub(crate) fn isolate() -> Result<(), PolicyError> {
    isolate_with(
        || std::fs::read_link("/proc/thread-self/ns/net").map_err(|_| ()),
        || unshare(CloneFlags::CLONE_NEWNET).map_err(|_| ()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::net::{TcpListener, TcpStream};
    use std::process::Command;
    use std::time::Duration;

    #[test]
    fn namespace_setup_fails_closed() {
        let calls = Cell::new(0);
        assert_eq!(
            isolate_with(|| Err(()), || {
                calls.set(1);
                Ok(())
            }),
            Err(PolicyError::Evaluation)
        );
        assert_eq!(calls.get(), 0);
        assert_eq!(
            isolate_with(|| Ok("net:[1]".into()), || Err(())),
            Err(PolicyError::Evaluation)
        );
        assert_eq!(
            isolate_with(|| Ok("net:[1]".into()), || Ok(())),
            Err(PolicyError::Evaluation)
        );
        let reads = Cell::new(0);
        assert_eq!(
            isolate_with(
                || {
                    reads.set(reads.get() + 1);
                    if reads.get() == 1 {
                        Ok("net:[1]".into())
                    } else {
                        Err(())
                    }
                },
                || Ok(())
            ),
            Err(PolicyError::Evaluation)
        );
        let reads = Cell::new(0);
        assert!(isolate_with(
            || {
                reads.set(reads.get() + 1);
                Ok(if reads.get() == 1 { "net:[1]" } else { "net:[2]" }.into())
            },
            || Ok(())
        )
        .is_ok());
    }

    // Run in a separate process: unshare changes the calling thread permanently.
    #[test]
    fn namespace_child_probe() -> Result<(), Box<dyn std::error::Error>> {
        let Some(address) = std::env::var_os("CITYOS_ZEN_NETWORK_PROBE") else {
            return Ok(());
        };
        let address = address
            .into_string()
            .map_err(|_| "invalid probe address")?
            .parse()?;
        if isolate().is_err() {
            println!("cityos-network-unavailable");
            return Ok(());
        }
        assert!(TcpStream::connect_timeout(&address, Duration::from_millis(300)).is_err());
        println!("cityos-network-isolated");
        Ok(())
    }

    #[test]
    fn namespace_blocks_host_loopback_or_reports_unavailable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        // Establish that the target is reachable from the host namespace.
        let _baseline = TcpStream::connect(listener.local_addr()?)?;
        let output = Command::new(std::env::current_exe()?)
            .arg("--exact")
            .arg("network::tests::namespace_child_probe")
            .arg("--nocapture")
            .env_clear()
            .env("CITYOS_ZEN_NETWORK_PROBE", listener.local_addr()?.to_string())
            .output()?;
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout)?;
        assert!(
            stdout.contains("cityos-network-isolated")
                || stdout.contains("cityos-network-unavailable")
        );
        Ok(())
    }
}
