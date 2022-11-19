// SPDX-License-Identifier: MIT
// Tells the Solidity compiler to compile only from v0.8.13 to v0.9.0
pragma solidity ^0.8.13;

import "./AggregatorLib.sol";

library AggregatorConfig {
    function fill_target_circuit_g2(uint256[] memory s, uint256 offset) internal view {
        s[offset] = uint256(1539647514328612786595421692225540920958187937684155529956894394534503985443);
        s[offset + 1] = uint256(14039811079704476632624877078606338467533386901928391587545625260228718375973);
        s[offset + 2] = uint256(8967532098595052333434229592845377892504787536141160885274644396471493891441);
        s[offset + 3] = uint256(18536008149478522570625651037279967836849855133622853146263111835499642859609);

        s[offset + 6] = uint256(1539647514328612786595421692225540920958187937684155529956894394534503985443);
        s[offset + 7] = uint256(14039811079704476632624877078606338467533386901928391587545625260228718375973);
        s[offset + 8] = uint256(12920710773244222888812176152411897196191523621156662777414393498173732317142);
        s[offset + 9] = uint256(3352234722360752651620754707977307251846456023674970516425926059145583348974);
    }

    function fill_verfiy_circuit_lagrange(uint256[] memory s, uint256 offset) internal view {
        
        s[offset + 0] = uint256(17982220847559514528666606524512600936613810912794619058101374759291091680317);
        s[offset + 1] = uint256(9452392313961155420795642412494757025428008986608118541982241939360597022014);
        
        s[offset + 3] = uint256(6438048111849715145797308160819481846096700047597734383853575420439011556043);
        s[offset + 4] = uint256(8079412196006941153666733099868647895041823269906502617457376904195890067848);
        
        s[offset + 6] = uint256(9681813629225159596152113087127390654234323674584338036692665151537270429393);
        s[offset + 7] = uint256(7533738542307941999498703450757555308903186695834619296545309257422921395527);
        
        s[offset + 9] = uint256(3576337907444948933229422075550118860306492453654734133198474333547455260719);
        s[offset + 10] = uint256(9489650436342344980432621339914995612521380276245626421719969231233341002276);
        
        s[offset + 12] = uint256(3572819547500459556493230921574441941323808714370343263166807032436772672177);
        s[offset + 13] = uint256(10218296438112894934083569673137750737354065858874748758332384992940936832957);
        
        s[offset + 15] = uint256(6411917550855518919663091506647042978595352194484674548075525574076192743647);
        s[offset + 16] = uint256(8909678826046754517843083175830090322177750593286052808571881072279600712517);
        
        s[offset + 18] = uint256(1239891546082445240512457603215994314691569254038864421927149112462173782185);
        s[offset + 19] = uint256(14247873892090987327260260012767837309865121978184019588686886197301848756078);
        
        s[offset + 21] = uint256(4766465886675297918399254492487266097376004928728543115638356066364588707417);
        s[offset + 22] = uint256(11437752614243290737244553678502285591820296801791253125671284517986707503313);
        
        s[offset + 24] = uint256(6526561186594704537492443308309261243924218134357451262736353090454843976792);
        s[offset + 25] = uint256(17098106681597307760734795811400797510517247593216608542801578042456217182790);
        
        
    }

    function update_hash_scalar(
        uint256 v,
        uint256[] memory absorbing,
        uint256 pos
    ) internal view {
        absorbing[pos++] = v;
    }

    function update_hash_point(
        uint256 x,
        uint256 y,
        uint256[] memory absorbing,
        uint256 pos
    ) internal view {
        //AggregatorLib.check_on_curve(x, y);
        absorbing[pos++] = (x << 1) | (y & 1);
        //absorbing[pos++] = y;
    }

    function to_scalar(bytes32 r) private view returns (uint256 v) {
        uint256 tmp = uint256(r);
        v =
            tmp %
            0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    }

    function hash(uint256[] memory absorbing, uint256 length)
        private
        view
        returns (bytes32[1] memory v)
    {
        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                2,
                add(absorbing, 0x20),
                length,
                v,
                32
            )
            switch success
            case 0 {
                invalid()
            }
        }
        assert(success);
    }

    function squeeze_challenge(uint256[] memory absorbing, uint256 length) internal view returns (uint256 v) {
        absorbing[length] = 0;
        bytes32 res = hash(absorbing, length * 32 + 1)[0];
        v = to_scalar(res);
        absorbing[0] = uint256(res);
        length = 1;
    }

    function get_chanllenges(
        uint256[] calldata transcript,
        uint256[] memory instance_commitment
    ) internal view returns (uint256[7] memory challenges) {
        uint256[] memory absorbing = new uint256[](94);
        uint256 pos = 0;
        uint256 transcript_pos = 0;
        update_hash_scalar(2048239651670500713024797663709869345102297737106168056944230908238674993888, absorbing, pos++);
        update_hash_point(instance_commitment[0], instance_commitment[1], absorbing, pos);
        pos +=  1;
        for (uint i = 0; i < 6; i ++) {
            update_hash_point(transcript[transcript_pos], transcript[transcript_pos + 1], absorbing, pos);
            transcript_pos += 2;
            pos +=  1;
        }
        // theta
        challenges[0] = squeeze_challenge(absorbing, pos);
        pos = 1;
        for (uint i = 0; i < 2; i ++) {
            update_hash_point(transcript[transcript_pos], transcript[transcript_pos + 1], absorbing, pos);
            transcript_pos += 2;
            pos +=  1;
        }
        // beta
        challenges[1] = squeeze_challenge(absorbing, pos);
        pos = 1;
        // gamma
        challenges[2] = squeeze_challenge(absorbing, pos);
        pos = 1;
        for (uint i = 0; i < 5; i ++) {
            update_hash_point(transcript[transcript_pos], transcript[transcript_pos + 1], absorbing, pos);
            transcript_pos += 2;
            pos +=  1;
        }
        // y
        challenges[3] = squeeze_challenge(absorbing, pos);
        pos = 1;
        for (uint i = 0; i < 4; i ++) {
            update_hash_point(transcript[transcript_pos], transcript[transcript_pos + 1], absorbing, pos);
            transcript_pos += 2;
            pos +=  1;
        }
        //x
        challenges[4] = squeeze_challenge(absorbing, pos);
        pos = 1;
        for (uint i = 0; i < 46; i ++) {
            update_hash_scalar(transcript[transcript_pos++], absorbing, pos++);
        }
        //v
        challenges[5] = squeeze_challenge(absorbing, pos);
        pos = 1;
        //u
        challenges[6] = squeeze_challenge(absorbing, pos);

        for (; transcript_pos < transcript.length; transcript_pos += 2) {
            AggregatorLib.check_on_curve(transcript[transcript_pos], transcript[transcript_pos + 1]);
        }
    }
}
