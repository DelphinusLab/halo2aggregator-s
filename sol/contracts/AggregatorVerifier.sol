// SPDX-License-Identifier: MIT
// Tells the Solidity compiler to compile only from v0.8.13 to v0.9.0
pragma solidity ^0.8.13;

import "./AggregatorLib.sol";
import "./AggregatorConfig.sol";

contract AggregatorVerifier {
    uint256 constant chunk_modulus = (1 << 90) - 1;

    function verify(
        uint256[] calldata proof,
        uint256[] calldata verify_instance,
        uint256[][] calldata target_instance
    ) public view {
        // step 0: verify target_instance commitment with target_instance
        for (uint256 i = 0; i < target_instance.length; i++) {
            uint256[] memory target_instance_buf = AggregatorConfig
                .calc_target_circuit_lagrange(target_instance[i]);

            uint256 x = verify_instance[i * 3 + 6] +
                ((verify_instance[i * 3 + 7] & chunk_modulus) << 180);
            uint256 y = (verify_instance[i * 3 + 8] << 90) +
                (verify_instance[i * 3 + 7] >> 90);
            require(x == target_instance_buf[0], "invalid instance x");
            require(y == target_instance_buf[1], "invalid instance y");
        }

        // step 1: calculate verify circuit instance commitment
        uint256[] memory verify_instance_buf = AggregatorConfig
            .calc_verfiy_circuit_lagrange(verify_instance);

        // step 2: calculate challenge
        uint256[7] memory challenge = AggregatorConfig.get_chanllenges(
            proof,
            verify_instance_buf
        );

        // step 3: calculate verify circuit pair
        uint256[] memory pairing_buf = new uint256[](24);
        {
            uint256[] memory buf = new uint256[](384);
            AggregatorConfig.verify_proof(
                proof,
                verify_instance_buf,
                challenge,
                buf
            );
            pairing_buf[12] = buf[128];
            pairing_buf[13] = buf[129];
            pairing_buf[18] = buf[192];
            pairing_buf[19] = buf[193];
        }

        // step 4: calculate target circuit pair from instance
        //w_x.x
        pairing_buf[0] =
            verify_instance[0] +
            ((verify_instance[1] & chunk_modulus) << 180);
        //w_x.y
        pairing_buf[1] =
            (verify_instance[2] << 90) +
            (verify_instance[1] >> 90);
        AggregatorLib.check_on_curve(pairing_buf[0], pairing_buf[1]);

        //w_g.x
        pairing_buf[6] =
            verify_instance[3] +
            ((verify_instance[4] & chunk_modulus) << 180);
        //w_g.y
        pairing_buf[7] =
            (verify_instance[5] << 90) +
            (verify_instance[4] >> 90);
        AggregatorLib.check_on_curve(pairing_buf[6], pairing_buf[7]);

        // step 5: do pairing
        AggregatorConfig.fill_circuits_g2(pairing_buf);
        bool checked = AggregatorLib.pairing(pairing_buf);
        require(checked, "pairing fail");
    }
}
