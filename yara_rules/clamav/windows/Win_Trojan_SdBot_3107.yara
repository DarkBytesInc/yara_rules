rule Win_Trojan_SdBot_3107
{
strings:
	$a0 = { 115e4508b7bb3613f7924958d1478a6b4fdf9ed603925c82642c9e5a38e6eb3c6f57d61bd2223bd04cb74e3e9bda63b6e34896fe9e90d1a10b3806db8047468fe6c98ac6193510636369b4c4060435d37007178d334d919f8cb4d07a2478d3dab58aa9b4f3abb8849fb729f1674e13de2b50b94c2c8ea325598e0e1011628ded }

condition:
	$a0
}

        