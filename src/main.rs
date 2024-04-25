use analyze::Analyzer;
use clap::Parser;

mod analyze;
mod cfg;
mod io;

#[derive(Parser)]
#[command(name = "check-cfi")]
#[command(version = "0.1")]
struct Cli {
    #[arg(help = "Path(s) to binary file")]
    files: Vec<String>,

    #[arg(short, long)]
    verbose: bool,

    #[arg(short, long)]
    backtrack_limit: Option<usize>,
}

fn main() {
    let cli = Cli::parse();
    let file_paths = cli.files;

    for path in &file_paths {
        eprintln!("Checking file: {}", path);

        match io::read_file(&path) {
            Ok((file_content, offset)) => {
                let mut analyzer = Analyzer::new(cli.backtrack_limit);
                analyzer.disassemble(&file_content, offset);
                analyzer.analyze();
                let (checked, unchecked) = analyzer.get_results();
                io::print_results(checked, unchecked, cli.verbose);
            }
            Err(e) => {
                eprintln!("Could not read file: {}\n", e);
                continue;
            }
        }
    }
}
