rule Win_Trojan_Bancos_1970
{
strings:
	$a0 = { 8d95b5c9b75748af241ac2901624c0b299862215190907b3320a1ed4c6d59bb5cc2ed6987b9a5ce6e846d845dda35e0abc91b6b43dc0abecc16e6d4fba99c02506ee56e855d1003d3201ece745b09c5f5c36beae797c1a0120 }

condition:
	$a0
}

        
