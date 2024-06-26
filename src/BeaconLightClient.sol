// This file is part of Darwinia.
// Copyright (C) 2018-2022 Darwinia Network
// SPDX-License-Identifier: GPL-3.0
//
// Darwinia is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Darwinia is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Darwinia. If not, see <https://www.gnu.org/licenses/>.
//
// Etherum beacon light client.
// Current arthitecture diverges from spec's proposed updated splitting them into:
// - Finalized header updates: To import a recent finalized header signed by a known sync committee by
// `import_finalized_header`.
// - Sync period updates: To advance to the next committee by `import_next_sync_committee`.
//
// To stay synced to the current sync period it needs:
// - Get sync_period_update at least once per period.
//
// To get light-client best finalized update at period N:
// - Fetch best finalized block's sync_aggregate_header in period N
// - Fetch parent_block/attested_block by sync_aggregate_header's parent_root
// - Fetch finalized_checkpoint_root and finalized_checkpoint_root_witness in attested_block
// - Fetch finalized_header by finalized_checkpoint_root
//
// - sync_aggregate -> parent_block/attested_block -> finalized_checkpoint -> finalized_header
//
// To get light-client sync period update at period N:
// - Fetch the finalized_header in light-client
// - Fetch the finalized_block by finalized_header.slot
// - Fetch next_sync_committee and next_sync_committee_witness in finalized_block
//
// - finalized_header -> next_sync_committee
//
// ```
//                       Finalized               Block   Sync
//                       Checkpoint              Header  Aggreate
// ----------------------|-----------------------|-------|---------> time
//                        <---------------------   <----
//                         finalizes               signs
// ```
//
// To initialize, it needs:
// - BLS verify contract
// - Trust finalized_header
// - current_sync_committee of the trust finalized_header
// - genesis_validators_root of genesis state
//
// When to trigger a committee update sync:
//
//  period 0         period 1         period 2
// -|----------------|----------------|----------------|-> time
//              | now
//               - active current_sync_committee
//               - known next_sync_committee, signed by current_sync_committee
//
//
// next_sync_committee can be imported at any time of the period, not strictly at the period borders.
// - No need to query for period 0 next_sync_committee until the end of period 0
// - After the import next_sync_committee of period 0, populate period 1's committee
//
// Inspired: https://github.com/ethereum/annotated-spec/blob/master/altair/sync-protocol.md

pragma solidity ^0.8.17;

import "./bls12381/BLS.sol";
import "./util/Bitfield.sol";
import "./BeaconLightClientUpdate.sol";

contract BeaconLightClient is BeaconLightClientUpdate, Bitfield {
    /// @dev Finalized beacon block header
    BeaconBlockHeader private finalized_header;
    /// @dev Finalized execution payload header block_number corresponding to `beacon.body_root` [New in Capella]
    uint256 private finalized_execution_payload_header_block_number;
    /// @dev Finalized execution payload header state_root corresponding to `beacon.body_root` [New in Capella]
    bytes32 private finalized_execution_payload_header_state_root;
    /// @dev Sync committees corresponding to the header
    /// sync_committee_perid => sync_committee_root
    mapping(uint64 => bytes32) public sync_committee_roots;

    /// @dev Beacon chain genesis validators root
    bytes32 public immutable GENESIS_VALIDATORS_ROOT;
    // A bellatrix beacon state has 25 fields, with a depth of 5.
    // | field                               | gindex | depth |
    // | ----------------------------------- | ------ | ----- |
    // | execution_payload                   | 25     | 4     |
    // | next_sync_committee                 | 55     | 5     |
    // | finalized_checkpoint_root           | 105    | 6     |
    uint64 private constant EXECUTION_PAYLOAD_INDEX = 25;
    uint64 private constant EXECUTION_PAYLOAD_DEPTH = 4;
    uint64 private constant NEXT_SYNC_COMMITTEE_INDEX = 55;
    uint64 private constant NEXT_SYNC_COMMITTEE_DEPTH = 5;
    uint64 private constant FINALIZED_CHECKPOINT_ROOT_INDEX = 105;
    uint64 private constant FINALIZED_CHECKPOINT_ROOT_DEPTH = 6;
    uint64 private constant SLOTS_PER_EPOCH = 32;
    uint64 private constant EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 256;
    bytes4 private constant DOMAIN_SYNC_COMMITTEE = 0x07000000;

    event FinalizedHeaderImported(BeaconBlockHeader finalized_header);
    event NextSyncCommitteeImported(
        uint64 indexed period,
        bytes32 indexed sync_committee_root
    );
    event FinalizedExecutionPayloadHeaderImported(
        uint256 block_number,
        bytes32 state_root
    );

    constructor(
        uint64 _slot,
        uint64 _proposer_index,
        bytes32 _parent_root,
        bytes32 _state_root,
        bytes32 _body_root,
        uint256 _block_number,
        bytes32 _merkle_root,
        bytes32 _current_sync_committee_hash,
        bytes32 _genesis_validators_root
    ) {
        finalized_header = BeaconBlockHeader(
            _slot,
            _proposer_index,
            _parent_root,
            _state_root,
            _body_root
        );
        finalized_execution_payload_header_block_number = _block_number;
        finalized_execution_payload_header_state_root = _merkle_root;
        sync_committee_roots[
            compute_sync_committee_period(_slot)
        ] = _current_sync_committee_hash;
        GENESIS_VALIDATORS_ROOT = _genesis_validators_root;
    }

    /// @dev Return beacon light client finalized header's slot
    /// @return slot
    function slot() public view returns (uint64) {
        return finalized_header.slot;
    }

    /// @dev Return execution payload block number
    /// @return block number
    function block_number() public view returns (uint256) {
        return finalized_execution_payload_header_block_number;
    }

    /// @dev Return execution payload state root
    /// @return merkle root
    function merkle_root() public view returns (bytes32) {
        return finalized_execution_payload_header_state_root;
    }

    /// @dev follow beacon api: /beacon/light_client/updates/?start_period={period}&count={count}
    function import_next_sync_committee(
        FinalizedHeaderUpdate calldata header_update,
        SyncCommitteePeriodUpdate calldata sc_update
    ) external {
        require(
            is_supermajority(header_update.sync_aggregate.sync_committee_bits),
            "!supermajor"
        );
        require(
            header_update.signature_slot >
                header_update.attested_header.beacon.slot &&
                header_update.attested_header.beacon.slot >=
                header_update.finalized_header.beacon.slot,
            "!skip"
        );
        verify_light_client_header(header_update);

        uint64 attested_period = compute_sync_committee_period(
            header_update.attested_header.beacon.slot
        );
        uint64 finalized_period = compute_sync_committee_period(
            header_update.finalized_header.beacon.slot
        );
        uint64 signature_period = compute_sync_committee_period(
            header_update.signature_slot
        );
        require(
            signature_period == finalized_period &&
                finalized_period == attested_period,
            "!period"
        );

        bytes32 singature_sync_committee_root = sync_committee_roots[
            signature_period
        ];
        require(singature_sync_committee_root != bytes32(0), "!missing");
        require(
            singature_sync_committee_root ==
                hash_tree_root(header_update.signature_sync_committee),
            "!sync_committee"
        );

        require(
            verify_signed_header(
                header_update.sync_aggregate,
                header_update.signature_sync_committee,
                header_update.fork_version,
                header_update.attested_header.beacon
            ),
            "!sign"
        );

        if (
            header_update.finalized_header.beacon.slot > finalized_header.slot
        ) {
            apply_light_client_update(header_update);
        }

        bytes32 next_sync_committee_root = hash_tree_root(
            sc_update.next_sync_committee
        );
        require(
            verify_next_sync_committee(
                next_sync_committee_root,
                sc_update.next_sync_committee_branch,
                header_update.attested_header.beacon.state_root
            ),
            "!next_sync_committee"
        );

        uint64 next_period = signature_period + 1;
        require(sync_committee_roots[next_period] == bytes32(0), "imported");
        sync_committee_roots[next_period] = next_sync_committee_root;
        emit NextSyncCommitteeImported(next_period, next_sync_committee_root);
    }

    /// @dev follow beacon api: /eth/v1/beacon/light_client/finality_update/
    function import_finalized_header(
        FinalizedHeaderUpdate calldata update
    ) external {
        require(
            is_supermajority(update.sync_aggregate.sync_committee_bits),
            "!supermajor"
        );
        require(
            update.signature_slot > update.attested_header.beacon.slot &&
                update.attested_header.beacon.slot >=
                update.finalized_header.beacon.slot,
            "!skip"
        );
        verify_light_client_header(update);

        uint64 finalized_period = compute_sync_committee_period(
            finalized_header.slot
        );
        uint64 signature_period = compute_sync_committee_period(
            update.signature_slot
        );
        require(
            signature_period == finalized_period ||
                signature_period == finalized_period + 1,
            "!signature_period"
        );
        bytes32 singature_sync_committee_root = sync_committee_roots[
            signature_period
        ];

        require(singature_sync_committee_root != bytes32(0), "!missing");
        require(
            singature_sync_committee_root ==
                hash_tree_root(update.signature_sync_committee),
            "!sync_committee"
        );

        require(
            verify_signed_header(
                update.sync_aggregate,
                update.signature_sync_committee,
                update.fork_version,
                update.attested_header.beacon
            ),
            "!sign"
        );

        require(
            update.finalized_header.beacon.slot > finalized_header.slot,
            "!new"
        );
        apply_light_client_update(update);
    }

    function verify_signed_header(
        SyncAggregate calldata sync_aggregate,
        SyncCommittee calldata sync_committee,
        bytes4 fork_version,
        BeaconBlockHeader calldata header
    ) internal view returns (bool) {
        // Verify sync committee aggregate signature
        uint256 participants = sum(sync_aggregate.sync_committee_bits);
        bytes[] memory participant_pubkeys = new bytes[](participants);
        uint64 n = 0;
        unchecked {
            for (uint64 i = 0; i < SYNC_COMMITTEE_SIZE; ++i) {
                uint256 index = i >> 8;
                uint256 sindex = (i / 8) % 32;
                uint256 offset = i % 8;
                if (
                    (uint8(sync_aggregate.sync_committee_bits[index][sindex]) >>
                        offset) &
                        1 ==
                    1
                ) {
                    participant_pubkeys[n++] = sync_committee.pubkeys[i];
                }
            }
        }

        bytes32 domain = compute_domain(
            DOMAIN_SYNC_COMMITTEE,
            fork_version,
            GENESIS_VALIDATORS_ROOT
        );
        bytes32 signing_root = compute_signing_root(header, domain);
        bytes memory message = abi.encodePacked(signing_root);
        bytes memory signature = sync_aggregate.sync_committee_signature;
        require(signature.length == BLSSIGNATURE_LENGTH, "!signature");
        return
            BLS.fast_aggregate_verify(participant_pubkeys, message, signature);
    }

    function apply_light_client_update(
        FinalizedHeaderUpdate calldata update
    ) internal {
        finalized_header = update.finalized_header.beacon;
        finalized_execution_payload_header_block_number = update
            .finalized_header
            .execution
            .block_number;
        finalized_execution_payload_header_state_root = update
            .finalized_header
            .execution
            .state_root;
        emit FinalizedHeaderImported(update.finalized_header.beacon);
        emit FinalizedExecutionPayloadHeaderImported(
            update.finalized_header.execution.block_number,
            update.finalized_header.execution.state_root
        );
    }

    function verify_light_client_header(
        FinalizedHeaderUpdate calldata update
    ) internal pure {
        require(
            verify_finalized_header(
                update.finalized_header.beacon,
                update.finality_branch,
                update.attested_header.beacon.state_root
            ),
            "!finalized_header"
        );
        require(
            verify_execution_payload(
                update.attested_header.execution,
                update.attested_header.execution_branch,
                update.attested_header.beacon.body_root
            ),
            "!attested_header_execution"
        );
        require(
            verify_execution_payload(
                update.finalized_header.execution,
                update.finalized_header.execution_branch,
                update.finalized_header.beacon.body_root
            ),
            "!finalized_header_execution"
        );
    }

    function verify_finalized_header(
        BeaconBlockHeader calldata header,
        bytes32[] calldata finality_branch,
        bytes32 attested_header_state_root
    ) internal pure returns (bool) {
        require(
            finality_branch.length == FINALIZED_CHECKPOINT_ROOT_DEPTH,
            "!finality_branch"
        );
        return
            is_valid_merkle_branch(
                hash_tree_root(header),
                finality_branch,
                FINALIZED_CHECKPOINT_ROOT_DEPTH,
                FINALIZED_CHECKPOINT_ROOT_INDEX,
                attested_header_state_root
            );
    }

    function verify_execution_payload(
        ExecutionPayloadHeader calldata header,
        bytes32[] calldata execution_branch,
        bytes32 beacon_header_body_root
    ) internal pure returns (bool) {
        require(
            execution_branch.length == EXECUTION_PAYLOAD_DEPTH,
            "!execution_branch"
        );
        return
            is_valid_merkle_branch(
                hash_tree_root(header),
                execution_branch,
                EXECUTION_PAYLOAD_DEPTH,
                EXECUTION_PAYLOAD_INDEX,
                beacon_header_body_root
            );
    }

    function verify_next_sync_committee(
        bytes32 next_sync_committee_root,
        bytes32[] calldata next_sync_committee_branch,
        bytes32 header_state_root
    ) internal pure returns (bool) {
        require(
            next_sync_committee_branch.length == NEXT_SYNC_COMMITTEE_DEPTH,
            "!next_sync_committee_branch"
        );
        return
            is_valid_merkle_branch(
                next_sync_committee_root,
                next_sync_committee_branch,
                NEXT_SYNC_COMMITTEE_DEPTH,
                NEXT_SYNC_COMMITTEE_INDEX,
                header_state_root
            );
    }

    function is_supermajority(
        bytes32[2] calldata sync_committee_bits
    ) internal pure returns (bool) {
        return sum(sync_committee_bits) * 3 >= SYNC_COMMITTEE_SIZE * 2;
    }

    function compute_sync_committee_period(
        uint64 slot_
    ) internal pure returns (uint64) {
        return slot_ / SLOTS_PER_EPOCH / EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
    }

    function sum(bytes32[2] memory x) internal pure returns (uint256) {
        return countSetBits(uint256(x[0])) + countSetBits(uint256(x[1]));
    }
}
