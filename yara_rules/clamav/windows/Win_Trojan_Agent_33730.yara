rule Win_Trojan_Agent_33730
{
strings:
	$a0 = { f77a734607952c85ed6977ba2604b75229541e7547b274851df80129cee9f4c7bab9ec378452edd44f52e11883484ca116a6c0e2ee551a6f0d2da7d63fd6aad037ed31f1c91be47ca25fda29249c6a177efcafde28fe73b3197bc157e2124d }

condition:
	$a0
}

        