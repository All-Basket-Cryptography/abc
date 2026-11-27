#![forbid(unsafe_code)]
//! Python SHA-256 bindings to the ABC portable core.

use abc_sha256::{digest, MessageTooLong, Sha256, IMPLEMENTATION_ID};
use pyo3::exceptions::{PyOverflowError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

const ABI_VERSION: u32 = 0x0001_0000;

fn overflow(error: MessageTooLong) -> PyErr {
    PyOverflowError::new_err(error.to_string())
}

#[pyfunction]
fn sha256<'py>(py: Python<'py>, message: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let output = digest(message).map_err(overflow)?;
    Ok(PyBytes::new(py, &output))
}

#[pyclass(module = "abc_crypto._native")]
struct Context {
    state: Option<Sha256>,
}

#[pymethods]
impl Context {
    #[new]
    fn new() -> Self {
        Self {
            state: Some(Sha256::new()),
        }
    }

    fn update(&mut self, message: &[u8]) -> PyResult<()> {
        let state = self.state.as_mut().ok_or_else(|| {
            PyValueError::new_err("The SHA-256 context has already been finalized")
        })?;
        state.update(message).map_err(overflow)
    }

    fn finalize<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let state = self.state.take().ok_or_else(|| {
            PyValueError::new_err("The SHA-256 context has already been finalized")
        })?;
        Ok(PyBytes::new(py, &state.finalize()))
    }

    fn reset(&mut self) {
        self.state = Some(Sha256::new());
    }
}

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("ABI_VERSION", ABI_VERSION)?;
    module.add("IMPLEMENTATION_ID", IMPLEMENTATION_ID)?;
    module.add_class::<Context>()?;
    module.add_function(wrap_pyfunction!(sha256, module)?)?;
    Ok(())
}
