use clap::Parser;

mod analyze;
mod io;

#[derive(Parser)]
#[command(name = "check-cfi")]
#[command(version = "0.1")]
struct Cli {
    #[arg(help = "Path to binary file")]
    file: String,

    #[arg(short, long)] 
    verbose: bool,

    #[arg(
        short,
        long,
        default_value = "0x0",
        help = "Memory offset of first instruction, given in hexadecimal.",
    )]
    offset: Option<String>,
}

fn main() {
    let cli = Cli::parse();
    let file_path = cli.file;
    // let file_path = "/home/hannes/Kth/mex/check-cfi/test/input/cfi_single_indirect";

    let offset = u64::from_str_radix(cli.offset.unwrap_or_default().trim_start_matches("0x"), 16)
        .unwrap_or_default();

    let file_content = io::read_file(&file_path);
    analyze::disassembled_iced(&file_content, offset);
}
