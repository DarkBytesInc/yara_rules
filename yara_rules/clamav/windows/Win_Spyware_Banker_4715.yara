rule Win_Spyware_Banker_4715
{
strings:
	$a0 = { 2a79618f9adf4078485d6d408a4cfba05af347b8b18a66f339ad586b23f19f5ba83de1a4ad5176a01ddaf3a024ad4ece97d441b1ff3ef06d8cc227ae2fbe5dbc9b2ef2ace3456d256cec1aa91595af4ebdfa0080d512c8c70207c7c0c2d6257b9285f459c305f856583312783fcd35959168b4c05f483458d64b1e537042 }

condition:
	$a0
}

        