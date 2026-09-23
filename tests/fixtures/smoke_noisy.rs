use std::io::Write;

fn main() {
    let mut output = std::io::stdout().lock();
    let block = [b'x'; 4096];
    loop {
        if output.write_all(&block).is_err() {
            break;
        }
    }
}
