rule Win_Trojan_Mybot_5628
{
strings:
	$a0 = { 3fe33cb6172219ac1e742a985485a462b94c708cfb6d3288db3315bd760047a529350d800e53b094fd7cc966ee12a9eace1c0ca6a5b33c3f276bbc3fe309890bc1fdb29b7e7a2afe5050a2e8074a53201b0e8a3da6e3afa4df3d4eac71ddda8a }

condition:
	$a0
}

        
