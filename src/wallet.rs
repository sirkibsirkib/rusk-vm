use std::collections::hash_map::Entry;
use std::collections::HashMap;

use dusk_abi::H256;
use signatory::{ed25519::Seed, PublicKeyed};
use signatory_dalek::Ed25519Signer as Signer;

use crate::digest::Digest;
use crate::state::{ContractState, NetworkState};

pub struct ManagedAccount {
    /// The balance in Dusk
    balance: u128,
    #[allow(unused)]
    nonce: u128,
    signer: Signer,
}

impl Default for ManagedAccount {
    fn default() -> Self {
        let seed = Seed::generate();
        let signer = Signer::from(&seed);

        ManagedAccount {
            balance: 0,
            nonce: 0,
            signer,
        }
    }
}

impl ManagedAccount {
    pub fn id(&self) -> H256 {
        self.signer.public_key().expect("cannot fail").digest()
    }

    pub fn update(&mut self, state: &ContractState) {
        self.balance = state.balance();
    }

    pub fn balance(&self) -> u128 {
        self.balance
    }

    pub fn public_key(&self) -> signatory::ed25519::PublicKey {
        self.signer.public_key().expect("never fails")
    }

    pub fn signer(&self) -> &Signer {
        &self.signer
    }

    // pub fn call_contract(
    //     &mut self,
    //     contract_id: &H256,
    //     value: u128,
    //     data: &[u8],
    // ) -> Result<Transaction, Error> {
    //     if self.balance >= value {
    //         self.nonce += 1;

    //         let transaction = Transaction::call_contract(
    //             self.id(),
    //             contract_id.clone(),
    //             self.nonce,
    //             value,
    //             data.into(),
    //             &self.signer,
    //         );
    //         Ok(transaction)
    //     } else {
    //         bail!("Insufficient balance")
    //     }
    // }

    // pub fn deploy_contract<B: Into<Vec<u8>> + AsRef<[u8]>>(
    //     &mut self,
    //     bytecode: B,
    //     value: u128,
    // ) -> Result<(Transaction, H256), ()> {
    //     if self.balance >= value {
    //         self.nonce += 1;

    //         let (transaction, contract_id) = Transaction::deploy_contract(
    //             self.id(),
    //             value,
    //             self.nonce,
    //             bytecode.into(),
    //             &self.signer,
    //         );

    //         Ok((transaction, contract_id))
    //     } else {
    //         Err(())
    //     }
    // }
}

pub struct Wallet(HashMap<String, ManagedAccount>);

impl Wallet {
    pub fn new() -> Self {
        let mut w = Wallet(HashMap::new());
        w.new_account("default").expect("conflict in empty hashmap");
        w
    }

    pub fn default_account(&self) -> &ManagedAccount {
        self.0.get("default").expect("No default account")
    }

    pub fn default_account_mut(&mut self) -> &mut ManagedAccount {
        self.0.get_mut("default").expect("No default account")
    }

    /// Create a new account with the given name,
    /// Returns an error if an account with that name already exists
    pub fn new_account<S: Into<String>>(
        &mut self,
        name: S,
    ) -> Result<&mut ManagedAccount, ()> {
        match self.0.entry(name.into()) {
            Entry::Vacant(v) => Ok(v.insert(ManagedAccount::default())),
            _ => Err(()),
        }
    }

    pub fn get_account(&self, name: &str) -> Option<&ManagedAccount> {
        self.0.get(name)
    }

    pub fn get_account_mut(
        &mut self,
        name: &str,
    ) -> Option<&mut ManagedAccount> {
        self.0.get_mut(name)
    }

    pub fn sync(&mut self, state: &NetworkState) {
        for (_, contract_state) in self.0.iter_mut() {
            if let Some(account_state) =
                state.get_contract_state(&contract_state.id())
            {
                contract_state.update(account_state);
            }
        }
    }
}