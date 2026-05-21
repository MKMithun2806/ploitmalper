use pyo3::prelude::*;

mod engine;

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    engine::dedup::register(m)?;
    engine::parser::register(m)?;
    engine::matcher::register(m)?;
    engine::msfrpc::register(m)?;
    Ok(())
}
