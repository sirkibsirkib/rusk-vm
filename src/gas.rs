// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.

// Gas units are chosen to be represented by u64 so that gas metering instructions can operate on
// them efficiently.

/// Type alias for gas
pub type Gas = u64;

#[derive(Debug, PartialEq, Eq)]
pub enum GasMeterResult {
    Proceed,
    OutOfGas,
}

impl GasMeterResult {
    pub fn is_out_of_gas(&self) -> bool {
        match *self {
            GasMeterResult::OutOfGas => true,
            GasMeterResult::Proceed => false,
        }
    }
}

#[derive(Debug)]
/// Struct to keep track of gas usage
pub struct GasMeter {
    limit: Gas,
    /// Amount of gas left from initial gas limit. Can reach zero.
    gas_left: Gas,
}

impl GasMeter {
    /// Creates a new `GasMeter` with given gas limits
    pub fn with_limit(gas_limit: Gas) -> GasMeter {
        GasMeter {
            limit: gas_limit,
            gas_left: gas_limit,
        }
    }

    /// Deduct specified amount of gas from the meter
    pub fn charge(&mut self, amount: Gas) -> GasMeterResult {
        let new_value = match self.gas_left.checked_sub(amount) {
            None => None,
            Some(val) => Some(val),
        };

        // We always consume the gas even if there is not enough gas.
        self.gas_left = new_value.unwrap_or_else(|| 0);

        match new_value {
            Some(_) => GasMeterResult::Proceed,
            None => GasMeterResult::OutOfGas,
        }
    }

    /// Returns how much gas left from the initial budget.
    pub fn gas_left(&self) -> Gas {
        self.gas_left
    }

    /// Returns how much gas was spent.
    pub fn spent(&self) -> Gas {
        self.limit - self.gas_left
    }
}
