const AggregatorLib = artifacts.require("AggregatorLib");
const AggregatorVerifier = artifacts.require("AggregatorVerifier");

module.exports = function(deployer) {
  deployer.deploy(AggregatorLib);
  deployer.link(AggregatorLib, AggregatorVerifier);
  deployer.deploy(AggregatorVerifier);
};
