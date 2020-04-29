use std::marker::PhantomData;

use crate::call_context::Resolver;
use crate::ops::*;
use crate::VMError;

use kelvin::ByteHash;
use wasmi::{
    self, FuncInstance, FuncRef, ModuleImportResolver, RuntimeArgs,
    RuntimeValue, Signature,
};

use crate::call_context::{CallContext, Invoke};

macro_rules! abi_resolver {
    ( $visibility:vis $name:ident < $h:ident > { $( $id:expr, $op_name:expr => $op:path ),* } ) => {

        #[doc(hidden)]
        #[derive(Clone, Default)]
        $visibility struct $name<$h> (PhantomData<$h>);

        impl<$h: ByteHash> ModuleImportResolver for $name<$h> {
            fn resolve_func(&self, field_name: &str, _signature: &Signature) -> Result<FuncRef, wasmi::Error>
            where $(
                $op : AbiCall<$name<$h>, $h>,
                )*
            {
                match field_name {
                    $(
                        $op_name => Ok(FuncInstance::alloc_host(
                            Signature::new(<$op as AbiCall<Self, $h>>::ARGUMENTS,
                                           <$op as AbiCall<Self, $h>>::RETURN),
                            $id,
                        ))
                    ),*

                    ,

                    _ => panic!("invalid function name {:?}", field_name)
                }
            }
        }

        impl<$h: ByteHash> Invoke<H> for $name<$h> {
            fn invoke(
                context: &mut CallContext<Self, $h>,
                index: usize,
                args: RuntimeArgs) -> Result<Option<RuntimeValue>, VMError> {

                match index {
                    $(
                        $id => <$op as AbiCall<Self, _>>::call(context, args)
                    ),*

                    ,

                    _ => panic!("invalid index {:?}", index)
                }
            }
        }

        impl<H: ByteHash> Resolver<H> for $name<$h> {}
    };
}

abi_resolver! {
    pub CompoundResolver<H> {
        0, "panic" => panic::Panic,
        1, "debug" => debug::Debug,
        2, "set_storage" => storage::SetStorage,
        3, "get_storage" => storage::GetStorage,
        4, "delete_storage" => storage::DeleteStorage,
        5, "argument" => argument::Argument,
        6, "call_contract" => call_contract::CallContract,
        7, "balance" => balance::Balance,
        8, "ret" => ret::Return,
        9, "self_hash" => self_hash::SelfHash,
        10, "gas" => gas::Gas,
        11, "opcode" => opcode::OpCode,
        12, "call_contract_operation" => call_contract::CallContractOp,
        110, "phoenix_store" => phoenix_ops::PhoenixStore,
        120, "phoenix_verify" => phoenix_ops::PhoenixVerify,
        130, "phoenix_credit" => phoenix_ops::PhoenixCredit,
        140, "bls_verify" => bls::BLS
    }
}
