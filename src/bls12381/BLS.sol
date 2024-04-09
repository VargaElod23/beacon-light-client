// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.17;

import "./Pairing.sol";

library BLS {
    using BLS12G1Affine for Bls12G1;

    /// @dev FastAggregateVerify
    ///
    /// @notice Verifies an AggregateSignature against a list of PublicKeys.
    /// PublicKeys must all be verified via Proof of Possession before running this function.
    /// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.3.4
    function fast_aggregate_verify(
        bytes[] memory pubkeys,
        bytes memory message,
        bytes memory signature
    ) public view returns (bool) {
        Bls12G1 memory apk = aggregate(pubkeys);
        Bls12G2 memory asig = BLS12G2Affine.deserialize(signature);
        Bls12G2 memory msg_g2 = BLS12G2Affine.hash_to_curve(message);
        return verify(apk, asig, msg_g2);
    }

    function aggregate(
        bytes[] memory keys
    ) internal view returns (Bls12G1 memory) {
        require(keys.length > 0, "empty");
        Bls12G1 memory agg_g1 = BLS12G1Affine.zero();
        for (uint256 i = 0; i < keys.length; i++) {
            bytes memory g1 = keys[i];
            agg_g1 = agg_g1.add(BLS12G1Affine.deserialize(g1));
        }
        require(!agg_g1.is_infinity(), "infinity");
        return agg_g1;
    }

    /// @dev Checks that a signature is valid for the octet string message under the public key PK
    /// See <https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.8>
    /// @param public_key Public key in BLS12-381 G1.
    /// @param signature Signature in BLS12-381 G2.
    /// @param message An octet string.
    /// @return Result, either VALID or INVALID.
    function verify(
        Bls12G1 memory public_key,
        Bls12G2 memory signature,
        Bls12G2 memory message
    ) internal view returns (bool) {
        Bls12G1[] memory a = new Bls12G1[](2);
        a[0] = BLS12G1Affine.neg_generator();
        a[1] = public_key;
        Bls12G2[] memory b = new Bls12G2[](2);
        b[0] = signature;
        b[1] = message;
        return BLS12Pairing.pairing(a, b);
    }

    function to_compressed_g1(
        bytes memory g1
    ) internal pure returns (bytes memory) {
        Bls12G1 memory p = BLS12G1Affine.deserialize(g1);
        return BLS12G1Affine.serialize(p);
    }

    function to_compressed_g2(
        bytes memory g2
    ) internal pure returns (bytes memory) {
        Bls12G2 memory p = BLS12G2Affine.deserialize(g2);
        return BLS12G2Affine.serialize(p);
    }
}
