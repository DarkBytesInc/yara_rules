rule Win_Trojan_Spambot_150
{
strings:
	$a0 = { fffffffff2d016f925e113fe2f16d97cab96529cc224a0b0f7c04aa5330b7eee1685546affff1ffdd22f670cfb2597d8c507f81798b47cd8e0fe44992a8876a481f7ffffffe203ddc8d7f45050e595d5c673a267a5adbb911ec4ee7bca58adc807ffffffe3aed23ce92b8ae58b13 }

condition:
	$a0
}

        
