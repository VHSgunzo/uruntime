fn main() {
    if std::env::args().nth(1).as_deref() == Some("--uruntime-version") {
        println!("v-rust-smoke-fixture");
    } else {
        std::process::exit(64);
    }
}
