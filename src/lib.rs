/*
  Copyright (c) 2018-present evan GmbH.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

//! ## About
//! This crate allows you to create,update and read DIDs based on sidetree implemetation.
//! For this purpose a [`VadePlugin`] implementation is exported: [`VadeSidetree`].
//!
//! ## VadeSidetree
//!
//! Supports creating, updating and getting DIDs and DID documents based on sidetree, therefore supports:
//!
//! - [`did_create`]
//! - [`did_resolve`]
//! - [`did_update`]
//!
//! ## Compiling vade_sidetree
//!
//! ```sh
//! cargo build --release
//! ```

//! [`did_create`]: https://docs.rs/vade_evan_substrate/*/vade_evan_substrate/vade_evan_substrate/struct.VadeEvanSubstrate.html#method.did_create
//! [`did_resolve`]: https://docs.rs/vade_evan_substrate/*/vade_evan_substrate/vade_evan_substrate/struct.VadeEvanSubstrate.html#method.did_resolve
//! [`did_update`]: https://docs.rs/vade_evan_substrate/*/vade_evan_substrate/vade_evan_substrate/struct.VadeEvanSubstrate.html#method.did_update
//! [`VadeSidetree `]: https://git.slock.it/equs/interop/vade/vade-sidetree
//! [`VadePlugin`]: https://docs.rs/vade/*/vade/trait.VadePlugin.html

pub mod datatypes;
#[cfg(feature = "sdk")]
mod in3_request_list;
mod vade_sidetree;
pub use self::vade_sidetree::*;
