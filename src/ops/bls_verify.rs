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
        if let [RuntimeValue::I32(sig), RuntimeValue::I32(pub_key), RuntimeValue::I32(msg_off), RuntimeValue::I32(msg_len)] =
            *args.as_ref()
        {
            context.memory(|a| {
                use dusk_bls12_381_sign::{Signature, APK};
                let msg: &[u8] = {
                    let msg_ofs = msg_off as usize;
                    let msg_len = msg_len as usize;
                    &a[msg_ofs..msg_ofs + msg_len]
                };
                let signature: Signature = {
                    const SIZE: usize = Signature::serialized_size();
                    let sig_start = sig as usize;
                    let sig_end = sig_start + SIZE;
                    let byte_slice = &a[sig_start..sig_end];
                    let mut sig_bytes = [0; SIZE];
                    sig_bytes.copy_from_slice(byte_slice);
                    Signature::from_bytes(&sig_bytes)
                        .map_err(|_| VMError::InvalidArguments)?
                };
                let public_key: APK = {
                    const SIZE: usize = APK::serialized_size();
                    let pub_key_start = pub_key as usize;
                    let pub_key_end = pub_key_start + SIZE;
                    let byte_slice = &a[pub_key_start..pub_key_end];
                    let mut sig_bytes = [0; SIZE];
                    sig_bytes.copy_from_slice(byte_slice);
                    APK::from_bytes(&sig_bytes)
                        .map_err(|_| VMError::InvalidArguments)?
                };
                let ret = match public_key.verify(&signature, msg) {
                    Ok(()) => 1,
                    Err(_) => 0,
                };
                Ok(Some(RuntimeValue::from(ret)))
            })
        } else {
            Err(VMError::InvalidArguments)
        }
    }
}
