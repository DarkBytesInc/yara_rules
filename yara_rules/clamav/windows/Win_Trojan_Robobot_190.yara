rule Win_Trojan_Robobot_190
{
strings:
	$a0 = { 143cb3ecd15518a2782b98d27a346ea717d701282c6be57a7c6204c22bc0cd5f4631cc5bd5919fcde20daf3b4ebdc8eec6d110084d1afecc1c10e8492bbbd5debbafc607e096fe5f0a4e4ab52bdfa8bb0f3bc3a8def1baa113f0e3b4022a5fcc08d483e1a7622d1fee6bb3e05a1363eb93f6835e9bd8cf1c5ae9bd93df0dcae0c89b420b47f959d3b9985bc2e02f97e3395a965c07ac }

condition:
	$a0
}

        