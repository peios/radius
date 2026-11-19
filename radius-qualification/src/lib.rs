//! Developer-only synthetic fixtures. No native authority or external sockets.
#![forbid(unsafe_code)]

pub mod campaign;
pub mod load;
pub mod protocol;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Only remove directories this invocation created exclusively.
pub struct Scratch(pub std::path::PathBuf);
impl Scratch {
    pub fn new(parent: &std::path::Path) -> Result<Self> {
        let path = parent.join(format!("radius-qualify-{}", radius_accounting::id()?));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
