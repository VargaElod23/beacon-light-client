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

pragma solidity ^0.8.17;

import "./trie/StorageProof.sol";
import "./BeaconLightClient.sol";

contract EthereumMessageRootOracle is BeaconLightClient {
    bytes32 public messageRoot =
        0x27ae5ba08d7291c96c8cbddcc148bf48a6d68c7974b94356f53754ef6171d757;

    address private constant ORMP = 0x00000000001523057a05d6293C1e5171eE33eE0A;
    bytes32 private constant SLOT =
        0x0000000000000000000000000000000000000000000000000000000000000006;

    struct Proof {
        bytes[] accountProof;
        bytes[] storageProof;
    }

    event FinalizedMessageRootImported(
        uint256 indexed blockNumber,
        bytes32 indexed messageRoot
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
    )
        BeaconLightClient(
            _slot,
            _proposer_index,
            _parent_root,
            _state_root,
            _body_root,
            _block_number,
            _merkle_root,
            _current_sync_committee_hash,
            _genesis_validators_root
        )
    {}

    function import_message_root(bytes calldata encodedProof) external {
        Proof memory proof = abi.decode(encodedProof, (Proof));
        bytes32 value = toBytes32(
            StorageProof.verify(
                merkle_root(),
                ORMP,
                proof.accountProof,
                SLOT,
                proof.storageProof
            )
        );
        require(value != messageRoot, "same");
        messageRoot = value;
        emit FinalizedMessageRootImported(block_number(), value);
    }

    function toBytes32(
        bytes memory source
    ) internal pure returns (bytes32 result) {
        require(source.length == 32, "!len");
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(add(source, 32))
        }
    }
}
