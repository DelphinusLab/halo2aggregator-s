const AggregatorLib = artifacts.require("AggregatorLib");
const AggregatorConfig = artifacts.require("AggregatorConfig");
const AggregatorVerifier = artifacts.require("AggregatorVerifier");

module.exports = function(deployer) {
  deployer.deploy(AggregatorLib);
  deployer.link(AggregatorLib, AggregatorConfig);
  deployer.deploy(AggregatorConfig);
  deployer.link(AggregatorLib, AggregatorVerifier);
  deployer.link(AggregatorConfig, AggregatorVerifier);
  deployer.deploy(AggregatorVerifier);
};
