// SPDX-License-Identifier: CC0-1.0

use super::init::core::Core;
use super::JetEnvironment;
use simplicity_sys::c_jets::frame_ffi::CFrameItem;

/// Type alias for the Core jet environment.
#[derive(Default, Debug)]
pub struct CoreEnv {
    _inner: (),
}

impl CoreEnv {
    pub fn new() -> Self {
        Self { _inner: () }
    }
}

impl JetEnvironment for CoreEnv {
    type Jet = Core;
    type CJetEnvironment = ();

    fn c_jet_env(&self) -> &Self::CJetEnvironment {
        &()
    }

    fn c_jet_ptr(
        jet: &Self::Jet,
    ) -> fn(&mut CFrameItem, CFrameItem, &Self::CJetEnvironment) -> bool {
        super::init::core::c_jet_ptr(jet)
    }
}
