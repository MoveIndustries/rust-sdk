#!/usr/bin/env bash
# Run confidential-assets e2e tests against a Movement localnet that has the
# confidential_asset module published.
#
# The localnet must be started by `scripts/start-localnet-confidential-assets.sh`
# from the `confidential-asset-prod` branch of
# https://github.com/movementlabsxyz/aptos-core
#
# Setup (one-time, in a separate directory):
#   git clone --branch confidential-asset-prod --depth 1 \
#       https://github.com/movementlabsxyz/aptos-core.git
#   cd aptos-core
#   ./scripts/start-localnet-confidential-assets.sh
#
# That script enables feature flag 87, publishes the confidential_asset module,
# and prints the publish-signer address. Export it as CONFIDENTIAL_MODULE_ADDRESS,
# then run this script from the rust-sdk root. It takes awhile because it builds 
# movement cli from the local branch.
# Usage:
#   export CONFIDENTIAL_MODULE_ADDRESS=0x<64 hex>
#   ./scripts/run-ca-e2e.sh [extra cargo test args]

set -euo pipefail

if [[ -z "${CONFIDENTIAL_MODULE_ADDRESS:-}" ]]; then
  echo "error: CONFIDENTIAL_MODULE_ADDRESS env var not set" >&2
  echo "" >&2
  echo "  Run scripts/start-localnet-confidential-assets.sh from the" >&2
  echo "  confidential-asset-prod branch of" >&2
  echo "  https://github.com/movementlabsxyz/aptos-core, then export" >&2
  echo "  the address it prints." >&2
  exit 1
fi

hex="${CONFIDENTIAL_MODULE_ADDRESS#0x}"
if [[ ${#hex} -ne 64 ]]; then
  echo "error: CONFIDENTIAL_MODULE_ADDRESS must be a 32-byte hex string (64 chars after 0x)" >&2
  echo "       got ${#hex} chars: $CONFIDENTIAL_MODULE_ADDRESS" >&2
  exit 1
fi

cargo test -p confidential-assets --features e2e --test e2e_lib \
  -- --ignored --test-threads=1 "$@"
