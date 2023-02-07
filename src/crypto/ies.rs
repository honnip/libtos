use crate::error::{IpfError, Result};
use std::{
    fmt,
    io::{self, Cursor, Read, Seek, SeekFrom},
};

pub(crate) struct IesReader<R: Read + Seek> {
    reader: R,
    cursor: Option<Cursor<String>>,
}

impl<R: Read + Seek> IesReader<R> {
    pub fn new(reader: R) -> Self {
        IesReader {
            reader,
            cursor: None,
        }
    }
}

impl<R: Read + Seek> Read for IesReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cursor.is_none() {
            let cursor = Cursor::new(IesTable::parse(&mut self.reader).unwrap().to_string());
            self.cursor = Some(cursor);
        }
        self.cursor.as_mut().unwrap().read(buf)
    }
}

struct IesTable {
    #[allow(dead_code)]
    header: IesHeader,
    columns: Vec<IesColumn>,
    rows: Vec<IesRow>,
}

impl fmt::Display for IesTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{}",
            self.columns
                .iter()
                .map(|column| column.to_string())
                .collect::<Vec<String>>()
                .join(",")
        )?;
        for row in &self.rows {
            writeln!(f, "{row}")?;
        }
        Ok(())
    }
}

impl IesTable {
    fn parse(mut reader: (impl Read + Seek)) -> Result<Self> {
        let header = IesHeader::parse(&mut reader)?;

        let mut int_columns = Vec::new();
        let mut str_columns = Vec::new();
        reader.seek(SeekFrom::Start(header.column_offset.into()))?;

        for _i in 0..header.column_count {
            let column = IesColumn::parse(&mut reader)?;
            if column.is_string {
                str_columns.push(column);
            } else {
                int_columns.push(column);
            }
        }
        int_columns.sort_by(|a, b| a.order.cmp(&b.order));
        str_columns.sort_by(|a, b| a.order.cmp(&b.order));
        int_columns.extend(str_columns);

        let mut rows = Vec::new();
        reader.seek(SeekFrom::Start(header.row_offset.into()))?;

        for _i in 0..header.row_count {
            let row = IesRow::parse(
                &mut reader,
                header.int_column_count,
                header.str_column_count,
            )?;
            rows.push(row);
        }

        Ok(Self {
            header,
            columns: int_columns,
            rows,
        })
    }
}

struct IesHeader {
    #[allow(dead_code)]
    name: String, // 128 bytes
    // unknown1: u32,
    column_offset: u32,
    row_offset: u32,
    #[allow(dead_code)]
    file_size: u32,
    // unknown2: u16,
    row_count: u16,
    column_count: u16,
    int_column_count: u16,
    str_column_count: u16,
    // unknown3: u16,
}

impl IesHeader {
    pub(crate) fn parse(mut reader: (impl Read + Seek)) -> Result<Self> {
        if reader.rewind().is_err() {
            return Err(IpfError::InvalidArchive("Failed to rewind the reader"));
        }
        let mut buffer = [0u8; 128 + 4 * 4 + 2 * 5];
        reader.read_exact(&mut buffer)?;

        let name = match String::from_utf8(buffer[0..128].into()) {
            Ok(string) => string.trim_end_matches(char::from(0)).into(),
            Err(err) => return Err(IpfError::Encoding(err)),
        };
        let offset_hint1 = u32::from_le_bytes(buffer[132..136].try_into().unwrap());
        let offset_hint2 = u32::from_le_bytes(buffer[136..140].try_into().unwrap());
        let file_size = u32::from_le_bytes(buffer[140..144].try_into().unwrap());

        let column_offset = file_size - offset_hint1 - offset_hint2;
        let row_offset = file_size - offset_hint2;

        // and next 2 bytes are unknown
        let row_count = u16::from_le_bytes(buffer[146..148].try_into().unwrap());
        let column_count = u16::from_le_bytes(buffer[148..150].try_into().unwrap());
        let int_column_count = u16::from_le_bytes(buffer[150..152].try_into().unwrap());
        let str_column_count = u16::from_le_bytes(buffer[152..154].try_into().unwrap());

        Ok(Self {
            name,
            column_offset,
            row_offset,
            file_size,
            row_count,
            column_count,
            int_column_count,
            str_column_count,
        })
    }
}

struct IesColumn {
    name1: String,
    #[allow(dead_code)]
    /// sometimes it is name1 with prefix "CT_", but mostly it is name1
    name2: String,
    is_string: bool,
    // unknown1: [u8; 5],
    order: u16,
}

impl fmt::Display for IesColumn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name1)
    }
}

impl IesColumn {
    ///  seek before calling this function
    pub(crate) fn parse(mut reader: (impl Read + Seek)) -> Result<Self> {
        let mut buffer = [0u8; 64 + 64 + 1 + 5 + 2];
        reader.read_exact(&mut buffer)?;

        let name1 = decrypt(buffer[0..64].into()).unwrap();
        let name2 = decrypt(buffer[64..128].into()).unwrap();
        let is_string = buffer[128] != 0;
        let order = u16::from_le_bytes(buffer[134..136].try_into().unwrap());

        Ok(Self {
            name1,
            name2,
            is_string,
            order,
        })
    }
}

struct IesRow {
    #[allow(dead_code)]
    /// every row has a *additional* class name
    class_name: String,
    cells: Vec<IesCell>,
}

impl fmt::Display for IesRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.cells
                .iter()
                .map(|cell| cell.to_string())
                .collect::<Vec<String>>()
                .join(",")
        )?;
        Ok(())
    }
}

impl IesRow {
    ///  seek before calling this function
    fn parse(mut reader: (impl Read + Seek), int_column: u16, string_column: u16) -> Result<Self> {
        let mut buffer = [0u8; 6];
        reader.read_exact(&mut buffer)?;
        let class_name_length = u16::from_le_bytes(buffer[4..6].try_into().unwrap());

        let mut buffer = vec![0u8; class_name_length.into()];
        reader.read_exact(&mut buffer)?;
        let class_name = decrypt(buffer).unwrap();

        let mut cells = Vec::new();

        for _i in 0..int_column {
            let cell = IesCell::parse_int(&mut reader)?;
            cells.push(cell);
        }

        for _i in 0..string_column {
            let cell = IesCell::parse_string(&mut reader)?;
            cells.push(cell);
        }

        // why
        reader.seek(SeekFrom::Current(string_column.into()))?;

        Ok(Self { cells, class_name })
    }
}

enum IesCell {
    Int(f32),
    Str(String),
}

impl fmt::Display for IesCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(value) => write!(f, "{value}"),
            Self::Str(value) => write!(f, "\"{value}\""),
        }
    }
}

impl IesCell {
    fn parse_int(mut reader: (impl Read + Seek)) -> Result<Self> {
        let mut buffer = [0u8; 4];
        reader.read_exact(&mut buffer)?;
        let value = f32::from_le_bytes(buffer);
        Ok(Self::Int(value))
    }

    fn parse_string(mut reader: (impl Read + Seek)) -> Result<Self> {
        let mut buffer = [0u8; 2];
        reader.read_exact(&mut buffer)?;
        let length = u16::from_le_bytes(buffer);

        let mut buffer = vec![0; length as usize];
        reader.read_exact(&mut buffer)?;
        let string = decrypt(buffer).unwrap();

        Ok(Self::Str(string))
    }
}

fn decrypt(mut bytes: Vec<u8>) -> Result<String> {
    for (idx, byte) in bytes.iter_mut().enumerate() {
        // trim NUL character
        if *byte == 0 {
            bytes.resize(idx, 0);
            break;
        }
        *byte ^= 1;
    }
    match String::from_utf8(bytes) {
        Ok(string) => Ok(string),
        Err(err) => Err(IpfError::Encoding(err)),
    }
}
