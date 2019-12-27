extern crate java_nom;
use structopt::StructOpt;
use std::path::PathBuf;

#[derive(StructOpt)]
#[structopt(name = "Java file parser")]
struct Opts {
    #[structopt(name = "FILE")]
    file: PathBuf,
}

fn main() {
    let opts = Opts::from_args();
    if let Ok(lines) = java_nom::read_lines(&opts.file) {
        for line in lines {
            println!("Line: {}", line);
        }
    }
}
