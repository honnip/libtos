use std::{
    borrow::Cow,
    convert::TryInto,
    io::{prelude::*, Seek, SeekFrom},
    path::PathBuf,
};

use crate::ipf_crypto::IpfCrypto;
use crate::result::{IpfError, IpfResult};

use path_clean::PathClean;

pub struct IpfEntry<'a> {
    reader: IpfEntryReader<'a>,
    header: Cow<'a, IpfEntryHeader>,
}

impl IpfEntry<'_> {
    /// Get name of archive.
    /// e.g. xml_tool.ipf
    pub fn archive_name(&self) -> PathBuf {
        PathBuf::from(self.header.archive_name.as_str()).clean()
    }

    /// Get path of entry excluding archive name.
    /// e.g. event_banner/event1234.png
    pub fn path(&self) -> PathBuf {
        PathBuf::from(self.header.file_name.as_str()).clean()
    }

    /// Get full path of file
    pub fn full_path(&self) -> PathBuf {
        let mut f = self.archive_name();
        f.push(self.path());
        f.clean()
    }

    /// Switch to encrypt mode
    /// read/write encrypted bytes
    pub fn encrypt(self) {
        self.reader.encrypt();
    }

    /// Switch to decrypt mode
    /// read/write decrypted bytes
    pub fn decrypt(self) {
        self.reader.decrypt();
    }

    /// switch to stored mode
    /// read/write pure bytes
    pub fn stored(self) {
        self.reader.stored();
    }
}

impl Read for IpfEntry<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct IpfEntryHeader {
    file_name: String,
    archive_name: String,
    #[allow(dead_code)]
    crc32: u32,
    compressed_size: u32,
    #[allow(dead_code)]
    uncompressed_size: u32,
    data_offset: u32,
}

impl IpfEntryHeader {
    fn parse(mut reader: (impl Read + Seek)) -> IpfResult<Self> {
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

    pub fn into_bytes(self) -> Vec<u8> {
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
    fn worth_compress(&self) -> bool {
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

enum IpfEntryReader<'a> {
    Stored(IpfCrypto<std::io::Take<&'a mut dyn Read>>),
    Deflate(flate2::read::DeflateDecoder<IpfCrypto<std::io::Take<&'a mut dyn Read>>>),
}

impl<'a> IpfEntryReader<'a> {
    fn encrypt(self) {
        match self {
            IpfEntryReader::Stored(mut r) => r.encrypt(),
            IpfEntryReader::Deflate(mut r) => r.get_mut().encrypt(),
        }
    }

    fn decrypt(self) {
        match self {
            IpfEntryReader::Stored(mut r) => r.decrypt(),
            IpfEntryReader::Deflate(mut r) => r.get_mut().decrypt(),
        }
    }

    fn stored(self) {
        match self {
            IpfEntryReader::Stored(mut r) => r.stored(),
            IpfEntryReader::Deflate(mut r) => r.get_mut().stored(),
        }
    }
}

impl Read for IpfEntryReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            IpfEntryReader::Stored(r) => r.read(buf),
            IpfEntryReader::Deflate(r) => r.read(buf),
        }
    }
}

pub(crate) struct IpfArchiveHeader {
    pub(crate) file_count: u16,
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
    fn parse(mut reader: (impl Read + Seek)) -> IpfResult<Self> {
        let mut buffer = [0u8; 24];
        if reader.seek(SeekFrom::End(-24)).is_err() {
            return Err(IpfError::InvalidArchive("Could not seek to header"));
        }
        reader.read_exact(&mut buffer)?;

        Ok(Self {
            file_count: u16::from_le_bytes(buffer[0..2].try_into().unwrap()),
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
        vec.extend_from_slice(&self.file_count.to_le_bytes());
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
    files: Vec<IpfEntryHeader>,
}

impl<R: Read + Seek> IpfArchive<R> {
    /// parse .ipf header from file
    pub fn new(mut reader: R) -> IpfResult<IpfArchive<R>> {
        let header = IpfArchiveHeader::parse(&mut reader)?;

        if header.signature != [0x50, 0x4B, 0x05, 0x06] {
            return Err(IpfError::InvalidArchive("Invalid magic signature"));
        }

        let mut files = Vec::with_capacity(header.file_count.into());
        reader.seek(SeekFrom::Start(header.local_file_offset.into()))?;

        // read local file tables
        for _ in 0..header.file_count {
            let data_table = IpfEntryHeader::parse(&mut reader)?;
            files.push(data_table);
        }

        Ok(Self {
            reader,
            header,
            files,
        })
    }

    /// Length of files
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// whether the archive is empty
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    pub fn by_index(&mut self, index: usize) -> IpfResult<IpfEntry> {
        if index >= self.len() {
            return Err(IpfError::FileNotFound);
        }
        let header = &self.files[index];

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
