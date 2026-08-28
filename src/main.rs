//! Goal: start the Infernal-Law process while keeping application and kernel
//! behavior in the testable library crate.

fn main() -> std::io::Result<()> {
    infernal_law::http::serve()
}
