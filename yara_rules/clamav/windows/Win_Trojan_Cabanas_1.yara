rule Win_Trojan_Cabanas_1
{
strings:
	$a0 = { 688b432083c080735b6681394d5a75548b793c3bc7724d03f9813f50450000754366817f044c01 }

condition:
	$a0
}

        
