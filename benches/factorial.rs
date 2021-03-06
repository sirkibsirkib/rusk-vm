// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use canonical::Id32;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rusk_vm::{Contract, GasMeter, NetworkState, Schedule, StandardABI};

fn get_config() -> Criterion {
    Criterion::default().sample_size(10)
}

fn factorial_3(
    network: &mut NetworkState<StandardABI<Blake2b>, Blake2b>,
    contract_id: Id32,
    gas: &mut GasMeter,
) {
    let n = 3;

    network
        .call_contract::<u64, u64>(contract_id, n, gas)
        .unwrap();
}

fn factorial_bench(c: &mut Criterion) {
    let code = include_bytes!(concat!(
        "../tests/contracts/",
        "factorial",
        "/target/wasm32-unknown-unknown/release/",
        "factorial",
        ".wasm"
    ));

    let schedule = Schedule::default();
    let contract = Contract::new(code, &schedule).unwrap();

    let mut network = NetworkState::<StandardABI<_>, Blake2b>::default();

    let contract_id = network.deploy(contract).unwrap();
    let mut gas = GasMeter::with_limit(1_000_000_000_000);
    c.bench_function("factorial 3", |b| {
        b.iter(|| {
            factorial_3(
                black_box(&mut network),
                black_box(contract_id),
                black_box(&mut gas),
            )
        })
    });
}

criterion_main!(factorial_main);
criterion_group!(name = factorial_main; config = get_config(); targets = factorial_bench);
