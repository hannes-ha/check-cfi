use analyze::Analyzer;
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

    let mut analyzer = Analyzer::new();
    analyzer.disassemble(&file_content, offset);
    analyzer.analyze();
    let (checked, unchecked) = analyzer.get_results();

    io::print_results(checked, unchecked, cli.verbose)
}
