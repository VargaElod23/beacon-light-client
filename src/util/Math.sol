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

library Math {
    /// Get the power of 2 for given input, or the closest higher power of 2 if the input is not a power of 2.
    /// Commonly used for "how many nodes do I need for a bottom tree layer fitting x elements?"
    /// Example: 0->1, 1->1, 2->2, 3->4, 4->4, 5->8, 6->8, 7->8, 8->8, 9->16.
    function get_power_of_two_ceil(uint256 x) internal pure returns (uint256) {
        if (x <= 1) return 1;
        else if (x == 2) return 2;
        else return 2 * get_power_of_two_ceil((x + 1) >> 1);
    }

    /// @dev Add with carry
    /// (carry, d) = a + b + carry.
    function adc(
        uint256 a,
        uint256 b,
        uint8 carry
    ) internal pure returns (uint8, uint256) {
        unchecked {
            uint256 c = a + b;
            uint256 d = c + uint256(carry);
            if (c < a || d < c) return (1, d);
            return (0, d);
        }
    }

    /// @dev Sub with borrow
    /// (borrow, d) = a - b - borrow.
    function sbb(
        uint256 a,
        uint256 b,
        uint8 borrow
    ) internal pure returns (uint8, uint256) {
        unchecked {
            uint256 c = a - uint256(borrow);
            if (b > c) return (1, (c - b));
            return (0, (c - b));
        }
    }
}
