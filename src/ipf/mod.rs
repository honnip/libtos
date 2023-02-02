use std::{
    borrow::Cow,
    convert::TryInto,
    io::{prelude::*, Seek, SeekFrom},
};

use crate::{
    crypto::IpfCrypto,
    entry::{IpfEntryHeader, IpfEntryReader},
};
use crate::{
    entry::IpfEntry,
    error::{IpfError, Result},
};

pub(crate) struct IpfArchiveHeader {
    pub(crate) entry_count: u16,
    pub(crate) local_file_offset: u32,
    #[allow(dead_code)]
    pub(crate) header_offset: u32,
    #[allow(dead_code)]
    pub(crate) signature: [u8; 4],
    #[allow(dead_code)]
    pub(crate) base_revision: u32,
    #[allow(dead_code)]
    pub(crate) revision: u32,
}

impl IpfArchiveHeader {
    fn parse(mut reader: (impl Read + Seek)) -> Result<Self> {
        let mut buffer = [0u8; 24];
        if reader.seek(SeekFrom::End(-24)).is_err() {
            return Err(IpfError::InvalidArchive(
                "Failed to seek to header (last 24 bits)",
            ));
        }
        reader.read_exact(&mut buffer)?;

        Ok(Self {
            entry_count: u16::from_le_bytes(buffer[0..2].try_into().unwrap()),
            local_file_offset: u32::from_le_bytes(buffer[2..6].try_into().unwrap()),
            // and next 2 bytes are always 0x00
            header_offset: u32::from_le_bytes(buffer[8..12].try_into().unwrap()),
            signature: buffer[12..16].try_into().unwrap(),
            base_revision: u32::from_le_bytes(buffer[16..20].try_into().unwrap()),
            revision: u32::from_le_bytes(buffer[20..24].try_into().unwrap()),
        })
    }

    pub fn into_bytes(self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(24);
        vec.extend_from_slice(&self.entry_count.to_le_bytes());
        vec.extend_from_slice(&self.local_file_offset.to_le_bytes());
        vec.extend_from_slice(&[0u8; 2]);
        vec.extend_from_slice(&self.header_offset.to_le_bytes());
        vec.extend_from_slice(&self.signature);
        vec.extend_from_slice(&self.base_revision.to_le_bytes());
        vec.extend_from_slice(&self.revision.to_le_bytes());
        vec
    }
}

impl From<IpfArchiveHeader> for Vec<u8> {
    fn from(header: IpfArchiveHeader) -> Vec<u8> {
        header.into_bytes()
    }
}

pub struct IpfArchive<R> {
    reader: R,
    #[allow(dead_code)]
    header: IpfArchiveHeader,
    entries: Vec<IpfEntryHeader>,
}

impl<R: Read + Seek> IpfArchive<R> {
    /// parse .ipf header from file
    pub fn new(mut reader: R) -> Result<IpfArchive<R>> {
        let header = IpfArchiveHeader::parse(&mut reader)?;

        if header.signature != [0x50, 0x4B, 0x05, 0x06] {
            return Err(IpfError::InvalidArchive(
                "Invalid magic signature. Not an IPF archive?",
            ));
        }

        let mut entries = Vec::with_capacity(header.entry_count.into());
        reader.seek(SeekFrom::Start(header.local_file_offset.into()))?;

        // read local file tables
        for _ in 0..header.entry_count {
            let data_table = IpfEntryHeader::parse(&mut reader)?;
            entries.push(data_table);
        }

        Ok(Self {
            reader,
            header,
            entries,
        })
    }

    /// Length of files
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// whether the archive is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn by_index(&mut self, index: usize) -> Result<IpfEntry> {
        if index >= self.len() {
            return Err(IpfError::FileNotFound);
        }
        let header = &self.entries[index];

        self.reader
            .seek(SeekFrom::Start(header.data_offset.into()))?;
        let limit_reader = (&mut self.reader as &mut dyn Read).take(header.compressed_size.into());

        if header.worth_compress() {
            let crypto = IpfCrypto::new(limit_reader);
            return Ok(IpfEntry {
                reader: IpfEntryReader::Deflate(flate2::read::DeflateDecoder::new(crypto)),
                header: Cow::Borrowed(header),
            });
        }
        let mut ipf = IpfCrypto::new(limit_reader);
        ipf.stored();
        Ok(IpfEntry {
            reader: IpfEntryReader::Stored(ipf),
            header: Cow::Borrowed(header),
        })
    }
}
