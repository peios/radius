//! Protected immutable credentials; Registry values hold only file references.
use crate::{
    model::{new_id, Record, Value, Values},
    runtime::SERVICE_SID,
};
use peios::{
    file::{fd_get_sd, SecInfo},
    security::{sddl, AceType, SecurityDescriptor, Sid, WellKnown},
};
use std::{
    fs::OpenOptions,
    io::{self, Read, Write},
    os::{
        fd::AsFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
pub fn material(path: &str, secret: bool, max: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let path = Path::new(path);
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid("credential path must be absolute"));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.nlink() != 1 || before.len() == 0 || before.len() > max as u64 {
        return Err(invalid("invalid credential file"));
    }
    let sd = fd_get_sd(file.as_fd(), SecInfo::OWNER | SecInfo::DACL).map_err(io::Error::from)?;
    let view = sd.view().map_err(io::Error::from)?;
    let system = Sid::well_known(WellKnown::System);
    let admins = Sid::well_known(WellKnown::Administrators);
    let service: Sid = SERVICE_SID.parse().map_err(io::Error::from)?;
    if view.owner() != Some(system.as_ref()) && view.owner() != Some(admins.as_ref()) {
        return Err(invalid("credential owner is not trusted"));
    }
    let dacl = view
        .dacl()
        .ok_or_else(|| invalid("credential file has an unrestricted DACL"))?;
    for ace in dacl.iter() {
        if ace.ace_type() == AceType::AccessDenied {
            continue;
        }
        if ace.ace_type() != AceType::AccessAllowed {
            return Err(invalid("unsupported credential file grant"));
        }
        let trusted = ace
            .sid()
            .is_some_and(|sid| sid == system.as_ref() || sid == admins.as_ref());
        let service_read = ace.sid() == Some(service.as_ref());
        // Public certificates may be read, but only trusted principals may
        // modify them or their security. Generic bits are treated conservatively.
        let read_only = ace.mask() & !(0xa0000000 | 0x001200a9) == 0;
        if !trusted && (!read_only || (secret && !service_read)) {
            return Err(invalid("credential file grants excessive access"));
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut file).take(max as u64 + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() > max
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.mtime() != after.mtime()
    {
        return Err(invalid("credential changed during read"));
    }
    Ok(bytes)
}

const DIRECTORY: &str = "/var/state/radius/credentials";
pub fn provision_directory() -> io::Result<()> {
    for path in ["/var/state/radius", DIRECTORY] {
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => continue,
            Ok(_) => return Err(invalid("credential directory is not a real directory")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        // Created carrying its SD, so it is never visible without it, and
        // directories that already existed keep their policy.
        let sd = sddl::parse(&format!(
            "O:BAG:BAD:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GRGX;;;{SERVICE_SID})"
        ))
        .map_err(io::Error::from)?;
        create_directory(path, &sd)?;
    }
    Ok(())
}
/// Create the directory `path` with `sd` supplied to the create. The handle is
/// a control handle, with no data right: nothing is read from it.
pub(super) fn create_directory(path: &str, sd: &SecurityDescriptor) -> io::Result<()> {
    use peios::file::{CreateOptions, Disposition, FileAccess, OpenFlags};
    peios::file::OpenOptions::new()
        .desired_access(FileAccess::READ_ATTRIBUTES | FileAccess::SYNCHRONIZE)
        .disposition(Disposition::Create)
        .options(CreateOptions::DIRECTORY)
        .flags(OpenFlags::SYMLINK_NOFOLLOW)
        .creator_sd(sd)
        .create(None, Path::new(path))
        .map(drop)
        .map_err(|e| io::Error::new(e.kind(), format!("cannot create {path}: {e}")))
}
pub fn read_input(path: &str, max: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("input must be a regular file"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut file).take(max as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > max {
        return Err(invalid("input size exceeds limits"));
    }
    Ok(bytes)
}
pub fn identity_values(
    staged: &mut Staged,
    certificate_files: &[String],
    private_key_file: &str,
) -> io::Result<Values> {
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
    let mut chain = Vec::new();
    for path in certificate_files {
        let bytes = read_input(path, 65536)?;
        if bytes.starts_with(b"-----BEGIN") {
            for cert in CertificateDer::pem_slice_iter(&bytes) {
                chain.push(
                    cert.map_err(|_| invalid("invalid PEM certificate"))?
                        .to_vec(),
                );
            }
        } else {
            chain.push(bytes.to_vec());
        }
    }
    if chain.is_empty() || chain.len() > 16 {
        return Err(invalid(
            "certificate chain must contain 1 to 16 certificates",
        ));
    }
    let raw = read_input(private_key_file, 65536)?;
    let key = if raw.starts_with(b"-----BEGIN") {
        PrivateKeyDer::from_pem_slice(&raw).map_err(|_| invalid("invalid PEM private key"))?
    } else {
        PrivateKeyDer::try_from(raw.to_vec()).map_err(|_| invalid("invalid DER private key"))?
    };
    radius_core::server_config(
        chain.iter().cloned().map(CertificateDer::from).collect(),
        key.clone_key(),
    )
    .map_err(|_| invalid("certificate and private key do not match"))?;
    let mut paths = Vec::new();
    for cert in chain {
        paths.push(staged.write(&cert)?);
    }
    let key_path = staged.write(key.secret_der())?;
    Ok(Values::from([
        ("CertificateFiles".into(), Value::List(paths)),
        ("PrivateKeyFile".into(), Value::Text(key_path)),
    ]))
}
#[derive(serde::Serialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub names: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub sha256: String,
}
pub fn inspect(record: &Record) -> io::Result<Vec<CertificateInfo>> {
    use x509_parser::{extensions::GeneralName, prelude::*};
    let mut result = Vec::new();
    for path in record
        .list("CertificateFiles")
        .ok_or_else(|| invalid("missing CertificateFiles"))?
    {
        let bytes = material(path, false, 65536)?;
        let (rest, cert) =
            parse_x509_certificate(&bytes).map_err(|_| invalid("invalid X.509 certificate"))?;
        if !rest.is_empty() {
            return Err(invalid("unexpected trailing certificate data"));
        }
        let names = cert
            .subject_alternative_name()
            .map_err(|_| invalid("invalid certificate names"))?
            .map(|s| {
                s.value
                    .general_names
                    .iter()
                    .filter_map(|n| match n {
                        GeneralName::DNSName(s) => Some((*s).to_owned()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        result.push(CertificateInfo {
            subject: cert.subject().to_string(),
            issuer: cert.issuer().to_string(),
            names,
            not_before: cert.validity().not_before.to_string(),
            not_after: cert.validity().not_after.to_string(),
            sha256: ring::digest::digest(&ring::digest::SHA256, &bytes)
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        });
    }
    Ok(result)
}
/// Failed writes remove their newly created files. Previously selected files are
/// preserved: another record or the daemon may still hold their contents.
#[derive(Default)]
pub struct Staged {
    paths: Vec<PathBuf>,
    committed: bool,
}
impl Drop for Staged {
    fn drop(&mut self) {
        if !self.committed {
            for p in &self.paths {
                let _ = std::fs::remove_file(p);
            }
        }
    }
}
impl Staged {
    pub fn write(&mut self, bytes: &[u8]) -> io::Result<String> {
        if bytes.is_empty() || bytes.len() > 65536 {
            return Err(invalid("invalid credential size"));
        }
        let dir = std::fs::symlink_metadata(DIRECTORY)?;
        if !dir.is_dir() || dir.file_type().is_symlink() {
            return Err(invalid("invalid credential directory"));
        }
        let path = Path::new(DIRECTORY).join(new_id().map_err(io::Error::other)?);
        let sd = sddl::parse(&format!(
            "O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;{SERVICE_SID})"
        ))
        .map_err(io::Error::from)?;
        let handle = peios::file::OpenOptions::new()
            .desired_access(peios::file::FileAccess::GENERIC_WRITE)
            .disposition(peios::file::Disposition::Create)
            .flags(peios::file::OpenFlags::SYMLINK_NOFOLLOW)
            .creator_sd(&sd)
            .open(None, &path)
            .map_err(io::Error::from)?;
        self.paths.push(path.clone());
        let owned: std::os::fd::OwnedFd = handle.into();
        let mut file = std::fs::File::from(owned);
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(path.to_string_lossy().into_owned())
    }
    pub fn committed(mut self) {
        self.committed = true;
    }
}
pub fn replace_secret(record: &Record, secret: &[u8]) -> io::Result<()> {
    if record.kind != crate::model::Kind::Client || !(16..=1024).contains(&secret.len()) {
        return Err(invalid("client secrets must contain 16 to 1024 bytes"));
    }
    let mut staged = Staged::default();
    let path = staged.write(secret)?;
    super::registry::write(
        &record.path(),
        &Values::from([("SecretFile".into(), Value::Text(path))]),
        false,
    )?;
    staged.committed();
    Ok(())
}
pub fn generated_secret() -> io::Result<Zeroizing<Vec<u8>>> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = Zeroizing::new(vec![0u8; 24]);
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("random source unavailable"))?;
    Ok(Zeroizing::new(
        bytes
            .iter()
            .flat_map(|b| format!("{b:02x}").into_bytes())
            .collect(),
    ))
}
pub fn import_identity(
    record: &Record,
    chain: Vec<Vec<u8>>,
    key: Zeroizing<Vec<u8>>,
) -> io::Result<()> {
    if record.kind != crate::model::Kind::Identity || chain.is_empty() || chain.len() > 16 {
        return Err(invalid("invalid server identity"));
    }
    let private = rustls::pki_types::PrivateKeyDer::try_from(key.to_vec())
        .map_err(|_| invalid("invalid DER private key"))?;
    radius_core::server_config(
        chain
            .iter()
            .cloned()
            .map(rustls::pki_types::CertificateDer::from)
            .collect(),
        private,
    )
    .map_err(|_| invalid("certificate and private key do not match"))?;
    let mut staged = Staged::default();
    let mut paths = Vec::new();
    for cert in &chain {
        paths.push(staged.write(cert)?);
    }
    let key_path = staged.write(&key)?;
    super::registry::write(
        &record.path(),
        &Values::from([
            ("CertificateFiles".into(), Value::List(paths)),
            ("PrivateKeyFile".into(), Value::Text(key_path)),
        ]),
        false,
    )?;
    staged.committed();
    Ok(())
}
