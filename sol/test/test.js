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

    instance = readBnLe(
      __dirname + "/../../output/verify-circuit_0.instance.data");

    const gas = await verifier.verify.estimateGas([], instance);
    console.log("gas cost", gas);
  });
});
