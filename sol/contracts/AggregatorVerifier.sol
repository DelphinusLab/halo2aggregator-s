// SPDX-License-Identifier: MIT
// Tells the Solidity compiler to compile only from v0.8.13 to v0.9.0
pragma solidity ^0.8.13;

import "./AggregatorLib.sol";
import "./AggregatorConfig.sol";

contract AggregatorVerifier {
    function verify_proof(
        uint256[] calldata proof,
        uint256[] memory instance,
        uint256[7] memory challenges,
        uint256[] memory pairing_buf
    ) private view {

	}

    function verify(
        uint256[] calldata proof,
        uint256[] calldata verify_instance,
        uint256[][] calldata target_instance
    ) public view {
        // step 1: compute verify circuit instance commitment
        uint256[] memory instance_buf = new uint256[](
            verify_instance.length * 3
        );
        for (uint256 i = 0; i < verify_instance.length; i++) {
            instance_buf[i * 3 + 2] = verify_instance[i];
        }
        AggregatorConfig.fill_verfiy_circuit_lagrange(instance_buf, 0);
        AggregatorLib.msm(instance_buf, 0, verify_instance.length);

        // step 2: compute challenges
        uint256[7] memory challenges = AggregatorConfig.get_chanllenges(
            proof,
            instance_buf
        );

        // step n: check pairing
        uint256 shift_modulus = (1 << 90) - 1;
        uint256[] memory pairing_buf = new uint256[](12);
        //w_x.x
        pairing_buf[0] =
            verify_instance[0] +
            ((verify_instance[1] & shift_modulus) << 180);
        //w_x.y
        pairing_buf[1] =
            (verify_instance[2] << 90) +
            (verify_instance[1] >> 90);
        //w_g.x
        pairing_buf[6] =
            verify_instance[0] +
            ((verify_instance[1] & shift_modulus) << 180);
        //w_g.y
        pairing_buf[7] =
            (verify_instance[2] << 90) +
            (verify_instance[1] >> 90);

        AggregatorConfig.fill_target_circuit_g2(pairing_buf, 2);

        {
            bool checked = AggregatorLib.pairing(pairing_buf);
            require(checked);
        }
    }
}
