rule Win_Trojan_FraudPack_9
{
strings:
	$a0 = { 558bec81ec48030000b9910100001b8d58fdffff09d1318d54fdffff218df8fcffff81c91e21000083f90075502395e8feffff2b9540fdffff29d281a54cfeffff2b300000818dbcfdffff5d0500002995c8fdffff29ca81e28d09000081f2440800000395d8feffff81f1d03b0000098d68fdffffff8df8fdffff31ca235584 }

condition:
	$a0
}

        
