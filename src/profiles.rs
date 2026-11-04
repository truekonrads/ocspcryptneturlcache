use anyhow::{bail, Context, Result};
use std::{
    collections::BTreeSet,
    env,
    ffi::OsString,
    io,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
};
use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
use winreg::{
    enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, REG_EXPAND_SZ, REG_SZ},
    types::FromRegValue,
    RegKey,
};

pub fn all_users() -> Result<Vec<PathBuf>> {
    let list = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
            KEY_READ | KEY_WOW64_64KEY,
        )
        .context("opening Windows ProfileList")?;
    let windows = PathBuf::from(env::var_os("SystemRoot").context("SystemRoot is unset")?);
    let current = env::var_os("USERPROFILE").map(PathBuf::from);
    from_profile_list(&list, &windows, current.as_deref())
}

fn from_profile_list(
    list: &RegKey,
    windows: &Path,
    current: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    let suffix = Path::new("AppData/LocalLow/Microsoft/CryptnetUrlCache");
    let mut paths = BTreeSet::new();
    if let Some(current) = current {
        paths.insert(current.join(suffix));
    }
    for name in list.enum_keys() {
        let name = name.context("enumerating Windows ProfileList")?;
        let profile = list
            .open_subkey(&name)
            .and_then(|key| key.get_raw_value("ProfileImagePath"))
            .with_context(|| format!("reading ProfileList\\{name}\\ProfileImagePath"))?;
        if !matches!(profile.vtype, REG_SZ | REG_EXPAND_SZ) {
            bail!("ProfileList\\{name}\\ProfileImagePath is not a string");
        }
        let mut path = OsString::from_reg_value(&profile)?;
        if profile.vtype == REG_EXPAND_SZ {
            path = expand(&path).context("expanding ProfileImagePath")?;
        }
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            bail!("ProfileList\\{name}\\ProfileImagePath is not an absolute path");
        }
        paths.insert(path.join(suffix));
    }
    // These are required even when service profiles are absent from ProfileList.
    for service in [
        "System32/config/systemprofile",
        "SysWOW64/config/systemprofile",
        "ServiceProfiles/LocalService",
        "ServiceProfiles/NetworkService",
    ] {
        paths.insert(windows.join(service).join(suffix));
    }
    Ok(paths.into_iter().collect())
}

fn expand(value: &OsString) -> Result<OsString> {
    let input: Vec<u16> = value.encode_wide().chain([0]).collect();
    // SAFETY: input is NUL-terminated; the first call only queries the buffer size.
    let size = unsafe { ExpandEnvironmentStringsW(input.as_ptr(), std::ptr::null_mut(), 0) };
    if size == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut output = vec![0; size as usize];
    // SAFETY: output contains size writable UTF-16 units, including the terminator.
    let written = unsafe { ExpandEnvironmentStringsW(input.as_ptr(), output.as_mut_ptr(), size) };
    if written == 0 {
        return Err(io::Error::last_os_error().into());
    }
    if written > size {
        bail!("environment changed while expanding profile path");
    }
    Ok(OsString::from_wide(&output[..written as usize - 1]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use winreg::{enums::HKEY_CURRENT_USER, types::ToRegValue};

    struct ProfileList {
        key: RegKey,
        path: String,
        dir: tempfile::TempDir,
    }

    impl ProfileList {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = format!(
                r"Software\cryptnet-dump-tests-{}-{}",
                std::process::id(),
                dir.path().file_name().unwrap().to_string_lossy()
            );
            let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(&path)
                .unwrap();
            Self { key, path, dir }
        }
    }

    impl Drop for ProfileList {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.path);
        }
    }

    #[test]
    fn system_and_service_accounts_find_registered_users_and_all_service_caches() {
        let list = ProfileList::new();
        let alice = list.dir.path().join("Relocated/Alïce");
        let (key, _) = list.key.create_subkey("S-1-5-21-test-user").unwrap();
        key.set_value("ProfileImagePath", &alice.as_os_str())
            .unwrap();
        let (key, _) = list.key.create_subkey("S-1-5-21-expanded").unwrap();
        let mut value = r"%SystemRoot%\DetachedProfile".to_reg_value();
        value.vtype = REG_EXPAND_SZ;
        key.set_raw_value("ProfileImagePath", &value).unwrap();
        let expanded = PathBuf::from(env::var_os("SystemRoot").unwrap()).join("DetachedProfile");
        let windows = list.dir.path().join("Windows");
        let suffix = "AppData/LocalLow/Microsoft/CryptnetUrlCache";
        let expected: BTreeSet<_> = [
            alice.join(suffix),
            expanded.join(suffix),
            windows.join("System32/config/systemprofile").join(suffix),
            windows.join("SysWOW64/config/systemprofile").join(suffix),
            windows.join("ServiceProfiles/LocalService").join(suffix),
            windows.join("ServiceProfiles/NetworkService").join(suffix),
        ]
        .into_iter()
        .collect();
        for current in [
            "System32/config/systemprofile",
            "SysWOW64/config/systemprofile",
            "ServiceProfiles/LocalService",
            "ServiceProfiles/NetworkService",
        ] {
            let paths =
                from_profile_list(&list.key, &windows, Some(&windows.join(current))).unwrap();
            assert_eq!(paths.len(), expected.len(), "duplicate roots for {current}");
            assert_eq!(paths.into_iter().collect::<BTreeSet<_>>(), expected);
        }
        assert_eq!(
            from_profile_list(&list.key, &windows, None)
                .unwrap()
                .into_iter()
                .collect::<BTreeSet<_>>(),
            expected
        );
    }

    #[test]
    fn unreadable_profile_registration_is_not_reported_as_complete_discovery() {
        let list = ProfileList::new();
        list.key.create_subkey("S-1-5-21-incomplete").unwrap();
        let error = from_profile_list(&list.key, list.dir.path(), None).unwrap_err();
        assert!(format!("{error:#}").contains("ProfileImagePath"));
    }
}
