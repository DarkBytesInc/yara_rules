rule Win_Trojan_Bancos_1771
{
strings:
	$a0 = { f2198e3dbae979ab59bc22ea02c7d4290d1c4146b7d9b5e33abf7c22ef2afa6b41f162b101fbd74c0e7d9fef21803f14987d086828b4753b938bb4684f44294154a3572818de }

condition:
	$a0
}

        
