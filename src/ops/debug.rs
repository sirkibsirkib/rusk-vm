// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::AbiCall;
use crate::call_context::{CallContext, Resolver};
use crate::VMError;

use canonical::Store;
use wasmi::{RuntimeArgs, RuntimeValue, ValueType};

pub struct Debug;

impl<E: Resolver<S>, S: Store> AbiCall<E, S> for Debug {
    const ARGUMENTS: &'static [ValueType] = &[ValueType::I32, ValueType::I32];
    const RETURN: Option<ValueType> = None;

    fn call(
        context: &mut CallContext<E, S>,
        args: RuntimeArgs,
    ) -> Result<Option<RuntimeValue>, VMError<S>> {
        if let &[RuntimeValue::I32(msg_ofs), RuntimeValue::I32(msg_len)] =
            args.as_ref()
        {
            context.memory(|a| {
                let msg_ofs = msg_ofs as usize;
                let msg_len = msg_len as usize;

                let slice = &a[msg_ofs..msg_ofs + msg_len];
                let str = std::str::from_utf8(slice)
                    .map_err(|_| VMError::InvalidUtf8)?;
                println!("CONTRACT DEBUG: {:?}", str);
                Ok(None)
            })
        } else {
            Err(VMError::InvalidArguments)
        }
    }
}
