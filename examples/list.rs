use libtos::IpfArchive;

fn main() {
    let file = std::fs::File::open("one_patch.ipf").unwrap();
    let mut ipf = IpfArchive::new(file).unwrap();

    for i in 0..ipf.len() {
        let entry = ipf.by_index(i).unwrap();
        println!(
            "{}/{}",
            entry.archive_name().display(),
            entry.path().display()
        );
    }
}
