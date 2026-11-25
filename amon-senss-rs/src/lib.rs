//! AMON-SENSS: scalable detection of DDoS attacks and creation of signatures
//! for attack filtering.
//!
//! Copyright (C) 2018 University of Southern California.
//! Rust port distributed under the same terms: GNU General Public License,
//! version 2 (see `COPYING`).
//!
//! The crate is primarily the `amonsenss` binary; the library exposes the
//! detector so it can be embedded or tested.

pub mod cnum;
pub mod config;
pub mod consts;
pub mod detector;
pub mod flow;
pub mod history;
pub mod input;
#[cfg(feature = "live")]
pub mod live;
pub mod net;

pub use config::Params;
pub use detector::Detector;
pub use flow::Flow;
pub use input::Format;
pub use net::{LocalPrefixes, Services};
