// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.17;

import "../util/Math.sol";
import "../util/ScaleCodec.sol";

/// @dev BLS12-381 prime field.
/// @param a High-order part 256 bits.
/// @param b Low-order part 256 bits.
struct Bls12Fp {
    uint256 a;
    uint256 b;
}

/// @title BLS12FP
library BLS12FP {
    using Math for uint256;

    /// @dev MOD_EXP precompile address.
    uint256 private constant MOD_EXP = 0x05;

    /// @dev Returns base field: q =
    /// 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    /// @return Base field.
    function q() internal pure returns (Bls12Fp memory) {
        return
            Bls12Fp(
                0x1a0111ea397fe69a4b1ba7b6434bacd7,
                0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
            );
    }

    function b() internal pure returns (Bls12Fp memory) {
        return Bls12Fp(0, 4);
    }

    /// @dev (q+1)/4
    function qr() internal pure returns (Bls12Fp memory) {
        return
            Bls12Fp(
                0x680447a8e5ff9a692c6e9ed90d2eb35,
                0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab
            );
    }

    /// @dev Returns the additive identity element of Bls12Fp.
    /// @return Bls12Fp(0, 0)
    function zero() internal pure returns (Bls12Fp memory) {
        return Bls12Fp(0, 0);
    }

    /// @dev Returns `true` if `self` is equal to the additive identity.
    /// @param self Bls12Fp.
    /// @return Result of zero check.
    function is_zero(Bls12Fp memory self) internal pure returns (bool) {
        return eq(self, zero());
    }

    function is_valid(Bls12Fp memory self) internal pure returns (bool) {
        return gt(q(), self);
    }

    /// @dev Returns `true` if `self` is equal or larger than r.
    /// @param self Bls12Fp.
    /// @return Result of check.
    function is_geq_modulus(Bls12Fp memory self) internal pure returns (bool) {
        return (eq(self, q()) || gt(self, q()));
    }

    /// @dev Returns `true` if `x` is equal to `y`.
    /// @param x Bls12Fp.
    /// @param y Bls12Fp.
    /// @return Result of equal check.
    function eq(
        Bls12Fp memory x,
        Bls12Fp memory y
    ) internal pure returns (bool) {
        return (x.a == y.a && x.b == y.b);
    }

    /// @dev Returns `true` if `x` is larger than `y`.
    /// @param x Bls12Fp.
    /// @param y Bls12Fp.
    /// @return Result of gt check.
    function gt(
        Bls12Fp memory x,
        Bls12Fp memory y
    ) internal pure returns (bool) {
        return (x.a > y.a || (x.a == y.a && x.b > y.b));
    }

    /// @dev Returns the result negative of `self`.
    /// @param self Bls12Fp.
    /// @return z `- self`.
    function neg(Bls12Fp memory self) internal pure returns (Bls12Fp memory z) {
        z = self;
        if (!is_zero(self)) {
            z = sub(q(), self);
        }
    }

    /// @dev Returns the result of `x + y`.
    /// @param x Bls12Fp.
    /// @param y Bls12Fp.
    /// @return z `x + y`.
    function add_nomod(
        Bls12Fp memory x,
        Bls12Fp memory y
    ) internal pure returns (Bls12Fp memory z) {
        unchecked {
            uint8 carry = 0;
            (carry, z.b) = x.b.adc(y.b, carry);
            (, z.a) = x.a.adc(y.a, carry);
        }
    }

    /// @dev Returns the result of `(x + y) % p`.
    /// @param x Bw6Fp.
    /// @param y Bw6Fp.
    /// @return z `(x + y) % p`.
    function add(
        Bls12Fp memory x,
        Bls12Fp memory y
    ) internal pure returns (Bls12Fp memory z) {
        z = add_nomod(x, y);
        z = subtract_modulus_to_norm(z);
    }

    function subtract_modulus_to_norm(
        Bls12Fp memory self
    ) internal pure returns (Bls12Fp memory z) {
        z = self;
        if (is_geq_modulus(self)) {
            z = sub(self, q());
        }
    }

    /// @dev Returns the result of `(x - y) % p`.
    /// @param x Bls12Fp.
    /// @param y Bls12Fp.
    /// @return z `(x - y) % p`.
    function sub(
        Bls12Fp memory x,
        Bls12Fp memory y
    ) internal pure returns (Bls12Fp memory z) {
        Bls12Fp memory m = x;
        if (gt(y, x)) {
            m = add_nomod(m, q());
        }
        unchecked {
            uint8 borrow = 0;
            (borrow, z.b) = m.b.sbb(y.b, borrow);
            (, z.a) = m.a.sbb(y.a, borrow);
        }
    }

    /// @dev Normalize Bls12Fp.
    /// @param fp Bls12Fp.
    /// @return `fp % p`.
    function norm(Bls12Fp memory fp) internal view returns (Bls12Fp memory) {
        uint256[8] memory input;
        input[0] = 0x40;
        input[1] = 0x20;
        input[2] = 0x40;
        input[3] = fp.a;
        input[4] = fp.b;
        input[5] = 1;
        input[6] = q().a;
        input[7] = q().b;
        uint256[2] memory output;

        assembly ("memory-safe") {
            if iszero(staticcall(gas(), MOD_EXP, input, 256, output, 64)) {
                let p := mload(0x40)
                returndatacopy(p, 0, returndatasize())
                revert(p, returndatasize())
            }
        }
        return Bls12Fp(output[0], output[1]);
    }

    function serialize(Bls12Fp memory x) internal pure returns (bytes memory) {
        return abi.encodePacked(uint128(x.a), x.b);
    }
}
