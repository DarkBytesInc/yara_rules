rule Win_Worm_Mytob_204
{
strings:
	$a0 = { 1b2f0f25debc0ca1c941396a33d18a622d557694b4159288bcafd962747427b8af26b533ed75c5ea55bfd9eba353003a29bddcbfed4a00662917024fba6e141847a0982a98f91cb0a95e0a2aecffdbf1aa3c90d9681fa78333cea3db340bebba7a890ad4fe14329e72a5c30ebe4e1811 }

condition:
	$a0
}

        