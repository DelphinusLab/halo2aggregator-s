const AggregatorLib = artifacts.require("AggregatorLib");
const AggregatorConfig = artifacts.require("AggregatorConfig");
const AggregatorVerifier = artifacts.require("AggregatorVerifier");

module.exports = function(deployer) {
  deployer.deploy(AggregatorLib);
  deployer.deploy(AggregatorConfig);
  deployer.link(AggregatorConfig, AggregatorVerifier);
  deployer.link(AggregatorLib, AggregatorVerifier);
  deployer.deploy(AggregatorVerifier);
};
