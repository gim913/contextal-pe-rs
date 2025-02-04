use pe_rs::PE;
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().len() == 1 {
        return Err("file names required".into());
    }

    for arg in std::env::args().skip(1) {
        let f = match File::open(&arg) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{}: ERROR: Can't open file: {}", arg, e);
                continue;
            }
        };
        let pe = match PE::new(f) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}: ERROR: {}", arg, e);
                continue;
            }
        };

        let ph = &pe.pe_header;
        println!("--- PE FILE HEADER ---");
        println!("Machine: {:#x} ({})", ph.Machine, ph.MachineStr);
        println!("NumberOfSections: {}", ph.NumberOfSections);
        println!("TimeDateStamp: {}", ph.TimeDateStampString);
        println!("PointerToSymbolTable: {:#x}", ph.PointerToSymbolTable);
        println!("NumberOfSymbols: {}", ph.NumberOfSymbols);
        println!("SizeOfOptionalHeader: {}", ph.SizeOfOptionalHeader);
        println!("Characteristics: {:?}", ph.CharacteristicsSymbols);

        let oh = &pe.optional_header;
        println!("--- IMAGE OPTIONAL HEADER ---");
        println!("Magic: {:#x} ({})", oh.Magic, oh.MagicStr);
        println!("Subsystem: {}", oh.SubsystemStr);
        println!("SizeOfHeaders: {:#x}", oh.SizeOfHeaders);
        println!("NumberOfRvaAndSizes: {}", oh.NumberOfRvaAndSizes);

        let mut snum = 1;
        for sec in &pe.section_headers {
            println!("--- SECTION {} HEADER ---", snum);
            println!("Name: {}", sec.Name);
            println!("VirtualSize: {:#x}", sec.VirtualSize);
            println!("VirtualAddress: {:#x}", sec.VirtualAddress);
            println!("SizeOfRawData: {}", sec.SizeOfRawData);
            println!("PointerToRawData: {}", sec.PointerToRawData);
            println!("Characteristics: {:?}", sec.CharacteristicsSymbols);
            snum += 1;
        }

        if pe.issues.is_empty() {
            println!("{}: OK", arg);
        } else {
            println!("{}: ISSUES: {:?}", arg, pe.issues);
        }
    }
    Ok(())
}
