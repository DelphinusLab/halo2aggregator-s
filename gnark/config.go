package main

type Halo2VerifierConfig struct {
	VerifyCircuitGLagrange [][]string `json: verify_circuit_g_lagrange`
	ChallengeInitScalar    string     `json: challenge_init_scalar`
	NbAdvices              uint32     `json: nb_advices`
	NbLookups              uint32     `json: nb_lookups`
	NbPermutationGroups    uint32     `json: nb_permutation_groups`
	Degree                 uint32     `json: degree`
	NbEvals                uint32     `json: nb_evals`
}
