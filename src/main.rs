//! Goal: start the Infernal-Law process while keeping application and kernel
//! behavior in the testable library crate.

fn main() -> std::io::Result<()> {
    let application =
        infernal_law::wiring::Application::from_env().map_err(std::io::Error::other)?;
    infernal_law::http::serve(application)
}
