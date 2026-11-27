//! Compile-time modules (providers.md): download modules live in [`download`]
//! (`src/modules/download/<id>/`, registered by `build.rs`); feed providers are configured
//! instances of them. Lookup modules are the `picket-lookup` crate's.

pub mod download;
