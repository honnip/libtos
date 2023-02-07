use libtos::IpfArchive;

fn main() {
    let file = std::fs::File::open("path/to/patch.ipf").unwrap();
    let mut ipf = IpfArchive::new(file).unwrap();

    for i in 0..ipf.len() {
        let entry = ipf.by_index(i).unwrap();
        println!("{}: {}", i, entry.full_path().display());
    }
}
