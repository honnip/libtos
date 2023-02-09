use std::io;

use libtos::{IpfArchive, IpfError};

fn main() -> Result<(), IpfError> {
    let mut ipf = IpfArchive::open("path/to/patch.ipf")?;
    for i in 0..ipf.len() {
        let mut entry = ipf.by_index(i)?;
        let path = std::path::Path::new("extract").join(entry.full_path());

        if let Some(p) = path.parent() {
            if !p.exists() {
                std::fs::create_dir_all(p).unwrap();
            }
        }
        let mut file = std::fs::File::create(path)?;
        io::copy(&mut entry, &mut file)?;
    }
    Ok(())
}
