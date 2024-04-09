// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.17;

import "./Fp2.sol";
import "../util/Bytes.sol";

/// @dev BLS12-381 G2 of affine coordinates in short Weierstrass.
/// @param x X over the quadratic extension field.
/// @param y Y over the quadratic extension field.
struct Bls12G2 {
    Bls12Fp2 x;
    Bls12Fp2 y;
}

/// @title BLS12G2Affine
library BLS12G2Affine {
    using Bytes for bytes;
    using BLS12FP for Bls12Fp;
    using BLS12FP2 for bytes;
    using BLS12FP2 for Bls12Fp2;

    /// @dev BLS12_381_G2ADD precompile address.
    uint256 private constant G2_ADD = 0x0f;
    // uint256 private constant G2_ADD = 0x0d;
    /// @dev BLS12_381_MAP_FP2_TO_G2 precompile address.
    uint256 private constant MAP_FP2_TO_G2 = 0x14;
    // uint256 private constant MAP_FP2_TO_G2 = 0x12;

    bytes1 private constant COMPRESION_FLAG = bytes1(0x80);
    bytes1 private constant INFINITY_FLAG = bytes1(0x40);
    bytes1 private constant Y_FLAG = bytes1(0x20);

    function zero() internal pure returns (Bls12G2 memory) {
        return Bls12G2(BLS12FP2.zero(), BLS12FP2.zero());
    }

    /// @dev Returns `true` if `x` is equal to `y`.
    /// @param a Bls12G2.
    /// @param b Bls12G2.
    /// @return Result of equal check.
    function eq(
        Bls12G2 memory a,
        Bls12G2 memory b
    ) internal pure returns (bool) {
        return a.x.eq(b.x) && a.y.eq(b.y);
    }

    function is_zero(Bls12G2 memory p) internal pure returns (bool) {
        return p.x.is_zero() && p.y.is_zero();
    }

    function is_infinity(Bls12G2 memory p) internal pure returns (bool) {
        return is_zero(p);
    }

    /// @dev Produce a hash of the message. This uses the IETF hash to curve's specification
    /// for Random oracle encoding (hash_to_curve) defined by combining these components.
    /// See <https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#section-3>
    /// @param message An arbitrary-length byte string..
    /// @return A point in Bls12G2.
    function hash_to_curve(
        bytes memory message
    ) internal view returns (Bls12G2 memory) {
        Bls12Fp2[2] memory u = message.hash_to_field();
        Bls12G2 memory q0 = map_to_curve(u[0]);
        Bls12G2 memory q1 = map_to_curve(u[1]);
        return add(q0, q1);
    }

    /// @dev Returns the result of `p + q`.
    /// @param p Bls12G2.
    /// @param q Bls12G2.
    /// @return `x + y`.
    function add(
        Bls12G2 memory p,
        Bls12G2 memory q
    ) internal view returns (Bls12G2 memory) {
        uint256[16] memory input;
        input[0] = p.x.c0.a;
        input[1] = p.x.c0.b;
        input[2] = p.x.c1.a;
        input[3] = p.x.c1.b;
        input[4] = p.y.c0.a;
        input[5] = p.y.c0.b;
        input[6] = p.y.c1.a;
        input[7] = p.y.c1.b;
        input[8] = q.x.c0.a;
        input[9] = q.x.c0.b;
        input[10] = q.x.c1.a;
        input[11] = q.x.c1.b;
        input[12] = q.y.c0.a;
        input[13] = q.y.c0.b;
        input[14] = q.y.c1.a;
        input[15] = q.y.c1.b;
        uint256[8] memory output;

        assembly ("memory-safe") {
            if iszero(staticcall(gas(), G2_ADD, input, 512, output, 256)) {
                let pt := mload(0x40)
                returndatacopy(pt, 0, returndatasize())
                revert(pt, returndatasize())
            }
        }

        return from(output);
    }

    /// @dev Map an arbitary field element to a corresponding curve point.
    /// @param fp2 Bls12Fp2.
    /// @return A point in G2.
    function map_to_curve(
        Bls12Fp2 memory fp2
    ) internal view returns (Bls12G2 memory) {
        uint256[4] memory input;
        input[0] = fp2.c0.a;
        input[1] = fp2.c0.b;
        input[2] = fp2.c1.a;
        input[3] = fp2.c1.b;
        uint256[8] memory output;

        assembly ("memory-safe") {
            if iszero(
                staticcall(gas(), MAP_FP2_TO_G2, input, 128, output, 256)
            ) {
                let p := mload(0x40)
                returndatacopy(p, 0, returndatasize())
                revert(p, returndatasize())
            }
        }

        return from(output);
    }

    /// @dev Derive Bls12G1 from uint256[8].
    /// @param x uint256[4].
    /// @return Bls12G2.
    function from(uint256[8] memory x) internal pure returns (Bls12G2 memory) {
        return
            Bls12G2(
                Bls12Fp2(Bls12Fp(x[0], x[1]), Bls12Fp(x[2], x[3])),
                Bls12Fp2(Bls12Fp(x[4], x[5]), Bls12Fp(x[6], x[7]))
            );
    }

    // Take a 192 byte array and convert to G2 point (x, y)
    function deserialize(
        bytes memory g2
    ) internal pure returns (Bls12G2 memory) {
        require(g2.length == 192, "!g2");
        bytes1 byt = g2[0];
        bool c_flag = (byt >> 7) & 0x01 == 0x01;
        bool b_flag = (byt >> 6) & 0x01 == 0x01;
        bool a_flag = (byt >> 5) & 0x01 == 0x01;
        if (a_flag && (!c_flag || b_flag)) {
            revert("!flag");
        }
        require(!c_flag, "compressed");
        require(!b_flag, "infinity");

        // Convert from array to FP2
        Bls12Fp memory x_imaginary = Bls12Fp(
            g2.slice_to_uint(0, 16),
            g2.slice_to_uint(16, 48)
        );
        Bls12Fp memory x_real = Bls12Fp(
            g2.slice_to_uint(48, 64),
            g2.slice_to_uint(64, 96)
        );
        Bls12Fp memory y_imaginary = Bls12Fp(
            g2.slice_to_uint(96, 112),
            g2.slice_to_uint(112, 144)
        );
        Bls12Fp memory y_real = Bls12Fp(
            g2.slice_to_uint(144, 160),
            g2.slice_to_uint(160, 192)
        );

        // Require elements less than field modulus
        require(
            x_imaginary.is_valid() &&
                x_real.is_valid() &&
                y_imaginary.is_valid() &&
                y_real.is_valid(),
            "!pnt"
        );

        Bls12Fp2 memory x = Bls12Fp2(x_real, x_imaginary);
        Bls12Fp2 memory y = Bls12Fp2(y_real, y_imaginary);

        Bls12G2 memory p = Bls12G2(x, y);
        require(!is_infinity(p), "infinity");
        return p;
    }

    // Take a G2 point (x, y) and compress it to a 96 byte array as the x-coordinate.
    function serialize(
        Bls12G2 memory g2
    ) internal pure returns (bytes memory r) {
        if (is_infinity(g2)) {
            r = new bytes(96);
            r[0] = bytes1(0xc0);
        } else {
            // Convert x-coordinate to bytes
            r = g2.x.serialize();

            // Record the leftmost bit of y_im to the a_flag1
            // If y_im happens to be zero, then use the bit of y_re
            // y_flag = (y_im * 2) // q if y_im > 0 else (y_re * 2) // q
            Bls12Fp memory q = BLS12FP.q();
            Bls12Fp memory y_re = g2.y.c0;
            Bls12Fp memory y_im = g2.y.c1;

            bool y_flag = y_im.is_zero()
                ? y_re.add_nomod(y_re).gt(q)
                : y_im.add_nomod(y_im).gt(q);
            if (y_flag) {
                r[0] = r[0] | Y_FLAG;
            }
            r[0] = r[0] | COMPRESION_FLAG;
        }
    }
}
