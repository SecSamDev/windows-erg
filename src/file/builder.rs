//! Builder for advanced raw file open options.

use std::path::{Path, PathBuf};

use crate::error::InvalidParameterError;
use crate::{Error, Result};

use super::raw::RawFile;

/// Builder for opening [`RawFile`] with custom tuning parameters.
pub struct RawFileBuilder {
    path: Option<PathBuf>,
    clusters_per_read: usize,
    metadata_buffer_capacity: usize,
}

impl RawFileBuilder {
    /// Create a new raw file builder.
    pub fn new() -> Self {
        Self {
            path: None,
            clusters_per_read: 16,
            metadata_buffer_capacity: 32_000,
        }
    }

    /// Set the source path.
    pub fn path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set how many clusters are attempted per read call.
    ///
    /// Minimum accepted value is 1.
    pub fn clusters_per_read(mut self, clusters_per_read: usize) -> Self {
        self.clusters_per_read = clusters_per_read.max(1);
        self
    }

    /// Set the internal metadata work buffer capacity.
    ///
    /// Minimum accepted value is 4096 bytes.
    pub fn metadata_buffer_capacity(mut self, metadata_buffer_capacity: usize) -> Self {
        self.metadata_buffer_capacity = metadata_buffer_capacity.max(4096);
        self
    }

    /// Open the configured raw file.
    pub fn open(self) -> Result<RawFile> {
        let path = self.path.ok_or_else(|| {
            Error::InvalidParameter(InvalidParameterError::new(
                "path",
                "Raw file source path must be specified",
            ))
        })?;

        RawFile::open_with_tuning(path, self.clusters_per_read, self.metadata_buffer_capacity)
    }
}

impl Default for RawFileBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::RawFileBuilder;
    use crate::Error;

    #[test]
    fn open_requires_path() {
        let result = RawFileBuilder::new().open();
        match result {
            Err(Error::InvalidParameter(e)) => {
                assert_eq!(e.parameter, "path");
            }
            _ => panic!("expected InvalidParameter error"),
        }
    }
}
