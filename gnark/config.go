package main

type Halo2VerifierProofData struct {
	Instance   [][]string `json:"instance"`
	Transcript []string   `json:"transcript"`
}

type Halo2VerifierConfig struct {
	VerifyCircuitGLagrange [][]string `json:"verify_circuit_g_lagrange"`
	VerifyCircuitG2Affine  [][]string `json:"verify_circuit_g2"`
	ChallengeInitScalar    string     `json:"challenge_init_scalar"`
	Degree                 uint32     `json:"degree"`
	NbAdvices              uint32     `json:"nb_advices"`
	NbLookups              uint32     `json:"nb_lookups"`
	NbPermutationGroups    uint32     `json:"nb_permutation_groups"`
	NbEvals                uint32     `json:"nb_evals"`
}
