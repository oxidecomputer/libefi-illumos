use libefi_illumos::*;

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
    let gpt = match Gpt::read(disk_name) {
        Ok(gpt) => gpt,
        Err(e) => {
            eprintln!("Cannot access GPT in: {disk_name}: {e}");
            return;
        }
    };

    println!("Block Size: {}", gpt.block_size());
    println!("Disk UUID: {}", gpt.guid());

    for partition in gpt.partitions() {
        println!("Partition {}", partition.index());
        println!("  start: {}", partition.start());
        println!("  size: {}", partition.size());
        println!("  tag: {:x}", partition.tag());
        println!("  GUID: {:?}", partition.partition_type_guid());
        println!("  name: {}", partition.name().to_string_lossy());
        println!("  UGUID: {}", partition.user_guid());
    }
}
