use std::{
    borrow::Cow,
    io::{Cursor, Read, Seek, Take},
    path::PathBuf,
};

use crate::crypto::{IesReader, IpfCrypto};
use crate::error::{IpfError, Result};

use flate2::read::DeflateDecoder;

pub struct IpfEntry<'a> {
    pub(crate) reader: IpfEntryReader<'a>,
    pub(crate) header: Cow<'a, IpfEntryHeader>,
}

impl IpfEntry<'_> {
    /// Get name of archive.
    /// e.g. example.ipf
    ///
    /// Sanitize before use
    pub fn archive_name(&self) -> PathBuf {
        self.header.archive_name()
    }

    /// Get file name.
    /// e.g. event1234.png, map.ies, blah.lua
    ///
    /// Sanitize before use
    pub fn file_name(&self) -> PathBuf {
        // note that header.file_name is path actually
        // so we need to get the last part
        self.header.file_name()
    }

    /// Get path of entry excluding archive name.
    /// e.g. event_banner/event1234.png
    ///
    /// Sanitize before use
    pub fn path(&self) -> PathBuf {
        self.header.path()
    }

    /// Get full path of file
    /// e.g. example.ipf/event_banner/event1234.png
    ///
    /// Sanitize before use
    pub fn full_path(&self) -> PathBuf {
        let mut f = self.archive_name();
        f.push(self.path());
        f
    }
}

impl Read for IpfEntry<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct IpfEntryHeader {
    pub(crate) file_name: String,
    pub(crate) archive_name: String,
    #[allow(dead_code)]
    pub(crate) crc32: u32,
    pub(crate) compressed_size: u32,
    #[allow(dead_code)]
    pub(crate) uncompressed_size: u32,
    pub(crate) data_offset: u32,
}

impl IpfEntryHeader {
    pub(crate) fn parse(mut reader: (impl Read + Seek)) -> Result<Self> {
        let mut buffer = [0u8; 20];
        reader.read_exact(&mut buffer)?;

        let file_name_length = u16::from_le_bytes(buffer[0..2].try_into().unwrap());
        let crc32 = u32::from_le_bytes(buffer[2..6].try_into().unwrap());
        let compressed_size = u32::from_le_bytes(buffer[6..10].try_into().unwrap());
        let uncompressed_size = u32::from_le_bytes(buffer[10..14].try_into().unwrap());
        let data_offset = u32::from_le_bytes(buffer[14..18].try_into().unwrap());
        let archive_name_length = u16::from_le_bytes(buffer[18..20].try_into().unwrap());

        let mut buffer = vec![0; archive_name_length.into()];
        reader.read_exact(&mut buffer)?;

        let archive_name = match String::from_utf8(buffer) {
            Ok(string) => string,
            Err(err) => return Err(IpfError::Encoding(err)),
        };

        let mut buffer = vec![0; file_name_length.into()];
        reader.read_exact(&mut buffer)?;

        let file_name = match String::from_utf8(buffer) {
            Ok(string) => string,
            Err(err) => return Err(IpfError::Encoding(err)),
        };

        Ok(Self {
            file_name,
            archive_name,
            crc32,
            compressed_size,
            uncompressed_size,
            data_offset,
        })
    }

    pub(crate) fn extension(&self) -> Option<String> {
        let extension = std::path::PathBuf::from(&self.file_name);
        extension
            .extension()
            .map(|ext| ext.to_string_lossy().to_string())
    }

    pub(crate) fn archive_name(&self) -> PathBuf {
        PathBuf::from(&self.archive_name)
    }

    pub(crate) fn file_name(&self) -> PathBuf {
        PathBuf::from(self.file_name.split('/').last().unwrap())
    }

    pub(crate) fn path(&self) -> PathBuf {
        PathBuf::from(&self.file_name)
    }

    fn into_bytes(self) -> Vec<u8> {
        let mut array = Vec::new();
        array.append(&mut self.file_name.len().to_le_bytes().into());
        array.append(&mut self.crc32.to_le_bytes().into());
        array.append(&mut self.compressed_size.to_le_bytes().into());
        array.append(&mut self.uncompressed_size.to_le_bytes().into());
        array.append(&mut self.data_offset.to_le_bytes().into());
        array.append(&mut self.archive_name.len().to_le_bytes().into());
        array.append(&mut self.archive_name.as_bytes().into());
        array.append(&mut self.file_name.as_bytes().into());
        array
    }

    /// do not compress and crypt these extensions
    pub(crate) fn worth_compress(&self) -> bool {
        const NOT_WORTH: [&str; 3] = ["jpg", "fsb", "mp3"];
        let extension = std::path::PathBuf::from(&self.file_name);
        let extension = match extension.extension() {
            Some(ext) => ext,
            None => return true,
        };

        for not_worth in NOT_WORTH {
            if extension.to_ascii_lowercase() == not_worth {
                return false;
            }
        }
        true
    }
}

impl From<IpfEntryHeader> for Vec<u8> {
    fn from(header: IpfEntryHeader) -> Vec<u8> {
        header.into_bytes()
    }
}

pub(crate) enum IpfEntryReader<'a> {
    Stored(Take<&'a mut dyn Read>),
    Ipf(DeflateDecoder<IpfCrypto<Take<&'a mut dyn Read>>>),
    Ies(IesReader<Cursor<Vec<u8>>>),
}

impl Read for IpfEntryReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            IpfEntryReader::Stored(r) => r.read(buf),
            IpfEntryReader::Ipf(r) => r.read(buf),
            IpfEntryReader::Ies(r) => r.read(buf),
        }
    }
}
