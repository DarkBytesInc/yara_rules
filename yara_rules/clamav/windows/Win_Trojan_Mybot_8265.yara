rule Win_Trojan_Mybot_8265
{
strings:
	$a0 = { d4e1b00bdff5a01353738433ed389dfebc9d076bba0fe78c0401cf9793e6640a8335939163773baa154f18728e0ebc13fb007594f936b3dfa113cc82332a576c2894da8abb42 }

condition:
	$a0
}

        
