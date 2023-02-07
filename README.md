# libtos

Supports reading of ipf and ies file format which are used in TreeOfSavior (and GranadoEspada)

```rust
use libtos::IpfArchive;

fn main() -> Result<(), IpfError> {
    let archive = IpfArchive::open("path/to/archive.ipf")?;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        println!("{}: {}", i, entry.full_path().display());   
    }
}
```
