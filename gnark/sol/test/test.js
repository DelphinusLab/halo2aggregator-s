const fs = require("fs");
const BN = require("bn.js");

const groth16Contract = artifacts.require("Verifier");
const proof = require("../../gnark_proof.json");
const inputs = require("../../gnark_inputs.json");


contract("groth16Contract", () => {
  it("test", async () => {
    const verifier = await groth16Contract.deployed();

    const gas = await verifier.verifyProof.estimateGas(
      [
        proof.Ar.X,
        proof.Ar.Y,
        proof.Krs.X,
        proof.Krs.Y,
        proof.Bs.X.A0,
        proof.Bs.X.A1,
        proof.Bs.Y.A0,
        proof.Bs.Y.A1,
      ],
      [proof.Commitments[0].X, proof.Commitments[0].Y],
      [proof.CommitmentPok.X, proof.CommitmentPok.Y],
      [inputs.Instance[0][0]]
    );
    console.log("gas cost", gas);

    const xy = await verifier.verifyProof([
      proof.Ar.X,
      proof.Ar.Y,
      proof.Krs.X,
      proof.Krs.Y,
      proof.Bs.X.A0,
      proof.Bs.X.A1,
      proof.Bs.Y.A0,
      proof.Bs.Y.A1,
    ],
      [proof.Commitments[0].X, proof.Commitments[0].Y],
      [proof.CommitmentPok.X, proof.CommitmentPok.Y],
      [inputs.Instance[0][0]]);
    console.log(xy.toString(16));
  });
});
