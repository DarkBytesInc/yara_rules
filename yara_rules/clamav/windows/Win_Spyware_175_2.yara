rule Win_Spyware_175_2
{
strings:
	$a0 = { e7e4c8038669e8ed21cb43e4e42ffcffff635555456b72858c0f9e2c13acc4123e6ecc556f582680fd1645dfe2ff066fc60f8da455d3246074d1aa670c1a13dfa0d0b72890cce15d48a7ec1f3d4088d5feffff3418f03a947f5d08f4dc3b42aa5cac08f672430b1dac8e07a5ffff2f9c52bdc80470f40d943bc10f8c3e447feb7519b54d5dd0ffffff2a1890840355cd6a8c54b0a76f }

condition:
	$a0
}

        