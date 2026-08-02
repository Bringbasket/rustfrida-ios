use common::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessIdentity {
    pid: i32,
    name: String,
    path: Option<String>,
}

impl ProcessIdentity {
    fn matches(&self, query: &str) -> bool {
        self.name == query
            || self.path.as_deref() == Some(query)
            || self.path.as_deref().and_then(path_basename) == Some(query)
    }

    fn display_name(&self) -> &str {
        self.path.as_deref().unwrap_or(&self.name)
    }
}

fn path_basename(path: &str) -> Option<&str> {
    path.rsplit('/').find(|component| !component.is_empty())
}

trait ProcessProvider {
    fn list_processes(&self) -> Result<Vec<ProcessIdentity>>;
    fn process_by_pid(&self, pid: i32) -> Result<Option<ProcessIdentity>>;
}

pub fn find_pid_by_name(name: &str) -> Result<i32> {
    let name = name.trim();
    if name.is_empty() {
        return Err(Error::InvalidArgument("--name must not be empty".into()));
    }

    find_pid_by_name_with(&SystemProcessProvider, name)
}

fn find_pid_by_name_with(provider: &dyn ProcessProvider, name: &str) -> Result<i32> {
    let mut matches: Vec<_> = provider
        .list_processes()?
        .into_iter()
        .filter(|process| process.pid > 0 && process.matches(name))
        .collect();
    matches.sort_by_key(|process| process.pid);
    matches.dedup_by_key(|process| process.pid);

    match matches.as_slice() {
        [] => Err(Error::State(format!(
            "no process exactly matching name `{name}` was found"
        ))),
        [matched] => {
            let pid = matched.pid;
            match provider.process_by_pid(pid)? {
                None => Err(Error::State(format!(
                    "process `{name}` (pid {pid}) exited before attach; retry --name or use --pid"
                ))),
                Some(current) if current.matches(name) => Ok(pid),
                Some(current) => Err(Error::State(format!(
                    "process `{name}` (pid {pid}) changed identity to `{}` before attach; retry --name",
                    current.display_name()
                ))),
            }
        }
        _ => {
            let details = matches
                .iter()
                .map(|process| format!("{} ({})", process.pid, process.display_name()))
                .collect::<Vec<_>>()
                .join(", ");
            Err(Error::State(format!(
                "process name `{name}` is ambiguous; matched {} processes: {details}; use --pid <PID>",
                matches.len()
            )))
        }
    }
}

struct SystemProcessProvider;

#[cfg(any(target_os = "ios", target_os = "macos"))]
impl ProcessProvider for SystemProcessProvider {
    fn list_processes(&self) -> Result<Vec<ProcessIdentity>> {
        apple::list_processes()
    }

    fn process_by_pid(&self, pid: i32) -> Result<Option<ProcessIdentity>> {
        apple::process_by_pid(pid)
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
impl ProcessProvider for SystemProcessProvider {
    fn list_processes(&self) -> Result<Vec<ProcessIdentity>> {
        Err(Error::Unsupported(
            "process-name attach is available only on Apple platforms; use --pid on this host".into(),
        ))
    }

    fn process_by_pid(&self, _pid: i32) -> Result<Option<ProcessIdentity>> {
        Err(Error::Unsupported(
            "process-name attach is available only on Apple platforms; use --pid on this host".into(),
        ))
    }
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod apple {
    use std::{ffi::c_void, io, mem, ptr};

    use common::{Error, Result};

    use super::ProcessIdentity;

    const PROC_ALL_PIDS: u32 = 1;
    const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
    const PROCESS_NAME_BUFFER_SIZE: usize = 1024;
    const EXTRA_PID_SLOTS: usize = 128;
    const MAX_ENUMERATION_ATTEMPTS: usize = 4;

    #[link(name = "proc")]
    extern "C" {
        fn proc_listpids(
            process_type: u32,
            type_info: u32,
            buffer: *mut c_void,
            buffer_size: libc::c_int,
        ) -> libc::c_int;
        fn proc_name(pid: libc::c_int, buffer: *mut c_void, buffer_size: u32) -> libc::c_int;
        fn proc_pidpath(pid: libc::c_int, buffer: *mut c_void, buffer_size: u32) -> libc::c_int;
    }

    pub(super) fn list_processes() -> Result<Vec<ProcessIdentity>> {
        let mut capacity = required_pid_slots()?.saturating_add(EXTRA_PID_SLOTS).max(256);

        for _ in 0..MAX_ENUMERATION_ATTEMPTS {
            let mut pids = vec![0_i32; capacity];
            let buffer_size = byte_size_for_pid_capacity(capacity)?;
            let bytes_written =
                unsafe { proc_listpids(PROC_ALL_PIDS, 0, pids.as_mut_ptr().cast::<c_void>(), buffer_size) };
            if bytes_written < 0 {
                return Err(Error::State(format!(
                    "proc_listpids failed while resolving --name: {}",
                    io::Error::last_os_error()
                )));
            }

            if bytes_written < buffer_size {
                let count = bytes_written as usize / mem::size_of::<i32>();
                pids.truncate(count);
                pids.sort_unstable();
                pids.dedup();

                let mut processes = Vec::with_capacity(pids.len());
                for pid in pids.into_iter().filter(|pid| *pid > 0) {
                    // A process may exit, or become inaccessible, between enumeration and lookup.
                    if let Ok(Some(process)) = process_by_pid(pid) {
                        processes.push(process);
                    }
                }
                return Ok(processes);
            }

            capacity = capacity
                .checked_mul(2)
                .ok_or_else(|| Error::State("process list grew beyond the supported enumeration size".into()))?;
        }

        Err(Error::State(
            "process list changed repeatedly while resolving --name; retry the command".into(),
        ))
    }

    pub(super) fn process_by_pid(pid: i32) -> Result<Option<ProcessIdentity>> {
        if pid <= 0 {
            return Ok(None);
        }

        let path = read_pid_path(pid);
        let name = read_pid_name(pid);
        if path.is_none() && name.is_none() {
            if process_has_exited(pid) {
                return Ok(None);
            }
            return Err(Error::State(format!(
                "libproc could not read the identity of pid {pid}; verify controller privileges"
            )));
        }

        let path = path.filter(|value| !value.is_empty());
        let name = name
            .filter(|value| !value.is_empty())
            .or_else(|| path.as_deref().and_then(super::path_basename).map(str::to_owned))
            .unwrap_or_else(|| format!("pid-{pid}"));
        Ok(Some(ProcessIdentity { pid, name, path }))
    }

    fn required_pid_slots() -> Result<usize> {
        let bytes = unsafe { proc_listpids(PROC_ALL_PIDS, 0, ptr::null_mut(), 0) };
        if bytes < 0 {
            return Err(Error::State(format!(
                "proc_listpids sizing failed while resolving --name: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(bytes as usize / mem::size_of::<i32>())
    }

    fn byte_size_for_pid_capacity(capacity: usize) -> Result<libc::c_int> {
        let bytes = capacity
            .checked_mul(mem::size_of::<i32>())
            .ok_or_else(|| Error::State("process list buffer size overflowed while resolving --name".into()))?;
        libc::c_int::try_from(bytes)
            .map_err(|_| Error::State("process list buffer exceeds the libproc size limit".into()))
    }

    fn read_pid_path(pid: i32) -> Option<String> {
        let mut buffer = vec![0_u8; PROC_PIDPATHINFO_MAXSIZE];
        let written = unsafe {
            proc_pidpath(
                pid,
                buffer.as_mut_ptr().cast::<c_void>(),
                PROC_PIDPATHINFO_MAXSIZE as u32,
            )
        };
        bytes_to_string(buffer, written)
    }

    fn read_pid_name(pid: i32) -> Option<String> {
        let mut buffer = vec![0_u8; PROCESS_NAME_BUFFER_SIZE];
        let written = unsafe {
            proc_name(
                pid,
                buffer.as_mut_ptr().cast::<c_void>(),
                PROCESS_NAME_BUFFER_SIZE as u32,
            )
        };
        bytes_to_string(buffer, written)
    }

    fn bytes_to_string(buffer: Vec<u8>, written: libc::c_int) -> Option<String> {
        if written <= 0 {
            return None;
        }
        let reported_len = usize::try_from(written).ok()?.min(buffer.len());
        let len = buffer[..reported_len]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(reported_len);
        Some(String::from_utf8_lossy(&buffer[..len]).into_owned())
    }

    fn process_has_exited(pid: i32) -> bool {
        if unsafe { libc::kill(pid, 0) } == 0 {
            return false;
        }
        io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }
}

#[cfg(test)]
mod tests {
    use common::Result;

    use super::{find_pid_by_name, find_pid_by_name_with, ProcessIdentity, ProcessProvider};

    struct FakeProvider {
        listed: Vec<ProcessIdentity>,
        current: Vec<ProcessIdentity>,
    }

    impl ProcessProvider for FakeProvider {
        fn list_processes(&self) -> Result<Vec<ProcessIdentity>> {
            Ok(self.listed.clone())
        }

        fn process_by_pid(&self, pid: i32) -> Result<Option<ProcessIdentity>> {
            Ok(self.current.iter().find(|process| process.pid == pid).cloned())
        }
    }

    fn process(pid: i32, name: &str, path: Option<&str>) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            name: name.into(),
            path: path.map(str::to_owned),
        }
    }

    fn provider(processes: Vec<ProcessIdentity>) -> FakeProvider {
        FakeProvider {
            listed: processes.clone(),
            current: processes,
        }
    }

    #[test]
    fn resolves_exact_process_name() {
        let provider = provider(vec![process(
            42,
            "SpringBoard",
            Some("/System/Library/CoreServices/SpringBoard"),
        )]);
        assert_eq!(find_pid_by_name_with(&provider, "SpringBoard").expect("pid"), 42);
    }

    #[test]
    fn resolves_exact_executable_path() {
        let path = "/Applications/Demo.app/Demo";
        let provider = provider(vec![process(91, "Demo", Some(path))]);
        assert_eq!(find_pid_by_name_with(&provider, path).expect("pid"), 91);
    }

    #[test]
    fn rejects_substring_matches() {
        let provider = provider(vec![process(42, "SpringBoard", None)]);
        let error = find_pid_by_name_with(&provider, "Spring").expect_err("substring must not match");
        assert!(error.to_string().contains("no process exactly matching"));
    }

    #[test]
    fn reports_ambiguous_matches_in_pid_order() {
        let provider = provider(vec![
            process(99, "Demo", Some("/private/var/Demo")),
            process(12, "Demo", Some("/Applications/Demo.app/Demo")),
        ]);
        let error = find_pid_by_name_with(&provider, "Demo").expect_err("multiple matches must fail");
        let message = error.to_string();
        assert!(message.contains("matched 2 processes"));
        assert!(message.find("12 (").expect("pid 12") < message.find("99 (").expect("pid 99"));
        assert!(message.contains("use --pid <PID>"));
    }

    #[test]
    fn reports_process_exit_during_revalidation() {
        let provider = FakeProvider {
            listed: vec![process(42, "Demo", None)],
            current: vec![],
        };
        let error = find_pid_by_name_with(&provider, "Demo").expect_err("exited process must fail");
        assert!(error.to_string().contains("exited before attach"));
    }

    #[test]
    fn reports_pid_identity_change_during_revalidation() {
        let provider = FakeProvider {
            listed: vec![process(42, "Demo", None)],
            current: vec![process(42, "Other", None)],
        };
        let error = find_pid_by_name_with(&provider, "Demo").expect_err("changed identity must fail");
        assert!(error.to_string().contains("changed identity"));
    }

    #[test]
    fn rejects_blank_name() {
        let error = find_pid_by_name("   ").expect_err("blank names must fail");
        assert!(error.to_string().contains("--name must not be empty"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn system_lookup_is_explicitly_unsupported_off_apple() {
        let error = find_pid_by_name("Demo").expect_err("host lookup must be unsupported");
        assert!(matches!(error, common::Error::Unsupported(_)));
        assert!(error.to_string().contains("use --pid"));
    }
}
