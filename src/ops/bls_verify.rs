// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::AbiCall;
use crate::call_context::CallContext;
use crate::VMError;

use canonical::Store;
use wasmi::{RuntimeArgs, RuntimeValue, ValueType};

pub struct BlsVerify;

impl<S: Store> AbiCall<S> for BlsVerify {
    const ARGUMENTS: &'static [ValueType] = &[
        ValueType::I32,
        ValueType::I32,
        ValueType::I32,
        ValueType::I32,
    ];
    const RETURN: Option<ValueType> = None;

    fn call(
        context: &mut CallContext<S>,
        args: RuntimeArgs,
    ) -> Result<Option<RuntimeValue>, VMError<S>> {
        use RuntimeValue as Rv;
        if let [Rv::I32(sig), Rv::I32(pub_key), Rv::I32(msg_off), Rv::I32(msg_len)] =
            *args.as_ref()
        {
            context.memory(|a| {
                use dusk_bls12_381_sign::{Signature, APK};
                let msg: &[u8] = {
                    let msg_start = msg_off as usize;
                    let msg_end = msg_start + msg_len as usize;
                    &a[msg_start..msg_end]
                };
                let signature: Signature = {
                    const SIZE: usize = Signature::serialized_size();
                    let sig_start = sig as usize;
                    let sig_end = sig_start + SIZE;
                    let byte_slice = &a[sig_start..sig_end];
                    let mut bytes = [0; SIZE];
                    bytes.copy_from_slice(byte_slice);
                    Signature::from_bytes(&bytes)
                        .map_err(|_| VMError::InvalidArguments)?
                };
                let public_key: APK = {
                    const SIZE: usize = APK::serialized_size();
                    let pub_key_start = pub_key as usize;
                    let pub_key_end = pub_key_start + SIZE;
                    let byte_slice = &a[pub_key_start..pub_key_end];
                    let mut bytes = [0; SIZE];
                    bytes.copy_from_slice(byte_slice);
                    APK::from_bytes(&bytes)
                        .map_err(|_| VMError::InvalidArguments)?
                };
                let success = public_key.verify(&signature, msg).is_ok();
                Ok(Some(RuntimeValue::from(if success { 1 } else { 0 })))
            })
        } else {
            Err(VMError::InvalidArguments)
        }
    }
}
