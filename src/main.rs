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

    #[arg(short, long)]
    limit_unchecked: Option<usize>,
}

fn main() {
    let cli = Cli::parse();
    let file_path = cli.file;
    // let file_path = "/home/hannes/Kth/mex/check-cfi/test/input/cfi_single_indirect";
    let (file_content, offset) = io::read_file(&file_path);
    let (checked, unchecked) = analyze::disassembled_iced(
        &file_content,
        offset,
        cli.limit_unchecked.unwrap_or_default(),
    );
    io::print_results(checked, unchecked, cli.verbose)
}
