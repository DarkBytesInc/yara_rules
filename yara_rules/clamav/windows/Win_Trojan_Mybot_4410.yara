rule Win_Trojan_Mybot_4410
{
strings:
	$a0 = { 8e4d3726505f26f53fc8afe0a9bcec0a1ae2c4f7d3d40a97a2c6dcfde938e2b85687066a2eb1f90c4fcb2c6900082b2a2d5398feac03121fe332f8fabaaabcafb3afc6f31ab0b4dc17407f9799ba2197487da39e5178fb11687a680f559d685545ac3f026eaa68255df62b2cb2242225bcfbb3e98d4c09b5fa9487497db8ebfbb09fa060cbf1ddd2401e66cdd7c2fdd5b11ad058d2a7 }

condition:
	$a0
}

        