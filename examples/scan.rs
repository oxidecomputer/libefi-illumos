use libefi_illumos::*;
use std::fs::File;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() <= 1 {
        println!("Try passing a path to a raw disk device as an argument");
        return;
    }

    for arg in &args[1..] {
        scan(&arg);
    }
}

fn scan(disk_name: &str) {
    let disk = File::open(disk_name).expect("Disk not found: {disk_name}");
    let gpt = match Gpt::new(disk) {
        Ok(gpt) => gpt,
        Err(e) => {
            eprintln!("Cannot access GPT in: {disk_name}: {e}");
            return;
        }
    };

    println!("Block Size: {}", gpt.block_size());
    println!("Disk UUID: {}", gpt.guid());

    for partition in gpt.partitions().filter(|part| part.size() != 0) {
        println!("Partition {}", partition.index());
        println!("  start: {}", partition.start());
        println!("  size: {}", partition.size());
        println!("  GUID: {:?}", partition.partition_type_guid());
        println!("  name: {}", partition.name().to_string_lossy());
        println!("  UGUID: {}", partition.user_guid());
    }
}
