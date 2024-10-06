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
}

fn main() {
    let cli = Cli::parse();
    let file_path = cli.file;
    // let file_path = "/home/hannes/Kth/mex/check-cfi/test/input/cfi_single_indirect";
    let (file_content, offset) = io::read_file(&file_path);
    analyze::disassembled_iced(&file_content, offset);
}
