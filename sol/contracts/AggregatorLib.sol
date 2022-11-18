pragma solidity ^0.8.13;

library AggregatorLib {
    function pairing(uint256[] memory input)
        internal
        view
        returns (bool)
    {
        uint256[1] memory result;
        bool ret;

        uint256 length = input.length * 0x20;
        assembly {
            ret := staticcall(
                gas(),
                8,
                add(input, 0x20),
                length,
                result,
                0x20
            )
        }
        require(ret);
        return result[0] != 0;
    }

    // The result will replaced at input[offset]
    // memory will be modified.
    function msm(
        uint256[] memory input,
        uint256 offset,
        uint256 length
    ) internal view {
        bool ret = false;
        uint256 start = 0;
        uint256 end = 0;

        for (uint256 pos = length; pos > 0; pos--) {
            start = 0x20 + offset * 0x20 + pos * 0x60 - 0x60;
            end = start + 0x20;
            assembly {
                ret := staticcall(
                    gas(),
                    7,
                    add(input, start),
                    0x60,
                    add(input, end),
                    0x40
                )
            }
            require(ret);

            start = end;
            end = end - 0x20;
            assembly {
                ret := staticcall(
                    gas(),
                    6,
                    add(input, start),
                    0x80,
                    add(input, end),
                    0x40
                )
            }
            require(ret);
        }
    }

    function update_hash_scalar(
        uint256 v,
        uint256[] memory absorbing,
        uint256 pos
    ) internal pure {
        absorbing[pos++] = 0x02;
        absorbing[pos++] = v;
    }

    function update_hash_point(
        uint256 x,
        uint256 y,
        uint256[] memory absorbing,
        uint256 pos
    ) internal pure {
        absorbing[pos++] = 0x01;
        absorbing[pos++] = x;
        absorbing[pos++] = y;
    }

    function to_scalar(bytes32 r) private pure returns (uint256 v) {
        v = uint256(r);
        // swap bytes
        v =
            ((v &
                0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >>
                8) |
            ((v &
                0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) <<
                8);

        // swap 2-byte long pairs
        v =
            ((v &
                0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >>
                16) |
            ((v &
                0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) <<
                16);

        // swap 4-byte long pairs
        v =
            ((v &
                0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >>
                32) |
            ((v &
                0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) <<
                32);

        // swap 8-byte long pairs
        v =
            ((v &
                0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >>
                64) |
            ((v &
                0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) <<
                64);

        // swap 16-byte long pairs
        v = (v >> 128) | (v << 128);
        v =
            v %
            0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    }

    function squeeze_challenge(uint256[] memory absorbing, uint32 length)
        internal
        view
        returns (uint256 v)
    {
        absorbing[length] = 0;
        bytes32 res = hash(absorbing, length * 32 + 1)[0];
        v = to_scalar(res);
        absorbing[0] = uint256(res);
        length = 1;
    }

    // sha2
    function hash(uint256[] memory absorbing, uint256 length)
        private
        view
        returns (bytes32[1] memory v)
    {
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 2, absorbing, length, v, 32)
            switch success
            case 0 {
                invalid()
            }
        }
        assert(success);
    }

    uint256 constant q_mod =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    function fr_pow(uint256 a, uint256 power) internal view returns (uint256) {
        uint256[6] memory input;
        uint256[1] memory result;
        bool ret;

        input[0] = 32;
        input[1] = 32;
        input[2] = 32;
        input[3] = a;
        input[4] = power;
        input[5] = q_mod;

        assembly {
            ret := staticcall(gas(), 0x05, input, 0xc0, result, 0x20)
        }
        require(ret);

        return result[0];
    }

    function fr_mul_add(
        uint256 a,
        uint256 b,
        uint256 c
    ) internal pure returns (uint256) {
        return addmod(mulmod(a, b, q_mod), c, q_mod);
    }

    function fr_add(uint256 a, uint256 b) internal pure returns (uint256) {
        return addmod(a, b, q_mod);
    }

    function fr_mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return mulmod(a, b, q_mod);
    }

    function fr_invert(uint256 a) internal view returns (uint256) {
        return fr_pow(a, q_mod - 2);
    }
}
