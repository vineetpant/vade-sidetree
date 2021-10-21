# Vade Sidetree Plugin

[![crates.io](https://img.shields.io/crates/v/vade-sidetree.svg)](https://crates.io/crates/vade-sidetree)
[![Documentation](https://docs.rs/vade-sidetree/badge.svg)](https://docs.rs/vade-sidetree:q)
[![Apache-2 licensed](https://img.shields.io/crates/l/vade-sidetree.svg)](./LICENSE.txt)

## About
This crate allows you to create,update and read DIDs based on sidetree implemetation.
For this purpose a [`VadePlugin`] implementation is exported: [`VadeSidetree`].

## VadeSidetree

Supports creating, updating and getting DIDs and DID documents based on sidetree, therefore supports:

- [`did_create`]
- [`did_resolve`]
- [`did_update`]

[`did_create`]: https://docs.rs/vade_evan_substrate/*/vade_evan_substrate/resolver/struct.VadeEvanSubstrate.html#method.did_create
[`did_resolve`]: https://docs.rs/vade_evan_substrate/*/vade_evan_substrate/resolver/struct.VadeEvanSubstrate.html#method.did_resolve
[`did_update`]: https://docs.rs/vade_evan_substrate/*/vade_evan_substrate/resolver/struct.VadeEvanSubstrate.html#method.did_update
[`VadeSidetree`]: https://git.slock.it/equs/interop/vade/vade-sidetree
[`Vade`]: https://docs.rs/vade/*/vade/struct.Vade.html
[`VadePlugin`]: https://docs.rs/vade/*/vade/trait.VadePlugin.html