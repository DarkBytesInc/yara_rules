rule Win_Trojan_Rufoll_1
{
strings:
	$a0 = { ffff57e8060000002a2e65786500ff55bc40743b488985c2fdffff5783c72c8bf7e878fcffff0bc07408fe8b1f154000742132c033c9fec983c108f3aa8b3c24ffb5c2fdffffff55c00bc075ceeb0433c0eb0cffb5c2fdffffff55c433c0408944241c61c31f7cc9ffad }

condition:
	$a0
}

        
