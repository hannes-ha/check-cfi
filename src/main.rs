use analyze::Analyzer;
use clap::Parser;

mod analyze;
mod cfg;
mod io;

#[derive(Parser)]
#[command(name = "check-cfi")]
#[command(version = "0.1")]
struct Args {
    #[arg(help = "Path(s) to binary file")]
    files: Vec<String>,

    #[arg(short, long)]
    verbose: bool,

    #[arg(short, long, help = "Output unchecked instructions")]
    unchecked: bool,

    #[arg(
        short = 'j',
        long,
        help = "Include indirect jumps in analysis [experimental]"
    )]
    enable_jumps: bool,

    #[arg(short, long, help = "Output checked instructions")]
    checked: bool,

    #[arg(
        short,
        long,
        help = "Limit the number of instructions visited during backtracking"
    )]
    backtrack_limit: Option<usize>,

    #[arg(short, long, help = "Specify output format: normal or csv")]
    format: Option<String>,
}

fn main() {
    let args = Args::parse();
    let file_paths = args.files;

    for path in &file_paths {
        eprintln!("File: {}", path);

        match io::read_file(&path) {
            Ok((file_content, offset, mut symbols)) => {
                let mut analyzer = Analyzer::new(args.backtrack_limit, args.enable_jumps);
                analyzer.disassemble(&file_content, offset, &mut symbols);
                analyzer.analyze();
                let (instr_checked, instr_unchecked) = analyzer.get_results();
                io::print_results(
                    instr_checked,
                    instr_unchecked,
                    args.checked,
                    args.unchecked,
                    &args.format,
                    &symbols,
                );
            }
            Err(e) => {
                eprintln!("Could not read file: {}\n", e);
                continue;
            }
        }
    }
}
