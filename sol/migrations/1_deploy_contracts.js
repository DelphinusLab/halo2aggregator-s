const AggregatorLib = artifacts.require("AggregatorLib");
const AggregatorConfig = artifacts.require("AggregatorConfig");
const AggregatorVerifierCoreStep1 = artifacts.require("AggregatorVerifierCoreStep1");
const AggregatorVerifierCoreStep2 = artifacts.require("AggregatorVerifierCoreStep2");
const AggregatorVerifier = artifacts.require("AggregatorVerifier");

module.exports = async function(deployer) {
  await deployer.deploy(AggregatorLib);

  deployer.link(AggregatorLib, AggregatorVerifierCoreStep1);
  step1 = await deployer.deploy(AggregatorVerifierCoreStep1);

  deployer.link(AggregatorLib, AggregatorVerifierCoreStep2);
  step2 = await deployer.deploy(AggregatorVerifierCoreStep2);

  deployer.link(AggregatorLib, AggregatorConfig);
  await deployer.deploy(AggregatorConfig);

  deployer.link(AggregatorLib, AggregatorVerifier);
  deployer.link(AggregatorConfig, AggregatorVerifier);
  await deployer.deploy(AggregatorVerifier, [step1.address, step2.address]);
};
