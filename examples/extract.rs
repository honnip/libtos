use std::io;

use libtos::{IpfArchive, IpfError};

fn main() -> Result<(), IpfError> {
    let mut ipf = IpfArchive::open("path/to/patch")?;
    for i in 0..ipf.len() {
        let mut entry = ipf.by_index(i)?;

        if let Some(p) = entry.full_path().parent() {
            if !p.exists() {
                std::fs::create_dir_all(p).unwrap();
            }
        }
        let mut file = std::fs::File::create(entry.full_path())?;
        io::copy(&mut entry, &mut file)?;
    }
    Ok(())
}
