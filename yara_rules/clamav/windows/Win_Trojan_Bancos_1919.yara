rule Win_Trojan_Bancos_1919
{
strings:
	$a0 = { 31dfdc242d2a9a9985f6782da33abb1a62087a41f95f1e44211f25b7a9dec8ece2cd434ad58f6688c62c57b3b02c0d41f5a13bb60907a01a5230715593da0834d6acacb7fcfee595ae172292de34b1d3e82fc63c8ebec4a04ac7 }

condition:
	$a0
}

        
