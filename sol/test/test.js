const fs = require("fs");
const BN = require("bn.js");

function readBnLe(file) {
  let buffer = fs.readFileSync(file
  );
  let buffer256 = [];
  for (let i = 0; i < buffer.length / 32; i++) {
    let v = new BN(0);
    let shift = new BN(1);
    for (let j = 0; j < 32; j++) {
      v = v.add(shift.muln(buffer[i * 32 + j]));
      shift = shift.muln(256);
    }
    buffer256.push(v);
  }

  return buffer256;
}

const AggregatorVerifier = artifacts.require("AggregatorVerifier");

contract('AggregatorVerifier', () => {
  it('test', async () => {
    const verifier = await AggregatorVerifier.deployed();

    const target_instance0 = readBnLe(
      __dirname + "/../../output/simple-circuit_0.instance.data");
    const target_instance1 = readBnLe(
      __dirname + "/../../output/simple-circuit_1.instance.data");

    const verify_instance = readBnLe(
      __dirname + "/../../output/verify-circuit_0.instance.data");

    const proof = readBnLe(
      __dirname + "/../../output/verify-circuit_0.transcript.data");

    const gas = await verifier.verify.estimateGas(proof, verify_instance, [target_instance0, target_instance1]);
    console.log("gas cost", gas);

    const xy = await verifier.verify(proof, verify_instance, [target_instance0, target_instance1]);
    console.log(xy.toString(16));
  });
});
