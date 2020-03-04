mod contracts;
mod helpers;

use kelvin::Blake2b;

use dusk_abi::ContractCall;
use rusk_vm::{Contract, GasMeter, NetworkState, Schedule, StandardABI};

#[test]
fn factorial() {
    use factorial::factorial;

    fn factorial_reference(n: u64) -> u64 {
        if n <= 1 {
            1
        } else {
            n * factorial_reference(n - 1)
        }
    }

    let code = contract_code!("factorial");

    let schedule = Schedule::default();
    let contract = Contract::new(code, &schedule).unwrap();

    let mut network = NetworkState::<StandardABI<_>, Blake2b>::default();

    let contract_id = network.deploy(contract).unwrap();

    let mut gas = GasMeter::with_limit(1_000_000_000);

    let n = 6;
    assert_eq!(
        network
            .call_contract(&contract_id, factorial(n), &mut gas)
            .unwrap(),
        factorial_reference(n)
    );
}

#[test]
fn hello_world() {
    let code = contract_code!("hello");

    let schedule = Schedule::default();
    let contract = Contract::new(code, &schedule).unwrap();

    let mut network = NetworkState::<StandardABI<_>, Blake2b>::default();

    let contract_id = network.deploy(contract).unwrap();

    let mut gas = GasMeter::with_limit(1_000_000_000);

    network
        .call_contract(&contract_id, ContractCall::<()>::nil(), &mut gas)
        .unwrap();
}

#[test]
fn transfer() {
    use transfer::transfer;

    let schedule = Schedule::default();
    let genesis_builder =
        ContractModule::new(contract_code!("transfer"), &schedule).unwrap();

    let genesis = genesis_builder.build().unwrap();

    // New genesis network with initial value
    let mut network = NetworkState::genesis(genesis, 1_000_000_000).unwrap();

    let genesis_id = *network.genesis_id();

    // Generate some items
    let item = Item::default();

    network.call_contract(genesis_id, transfer(item)).unwrap();

    // NOTE: not removing the temp dir here, as i currently want to check
    // if the info is actually written to disk.
}
