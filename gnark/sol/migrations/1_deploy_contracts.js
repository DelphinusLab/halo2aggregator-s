const Groth16Verifier = artifacts.require("Verifier");

module.exports = async function (deployer) {
  await deployer.deploy(Groth16Verifier);
};
