rule Win_Trojan_Mybot_112
{
strings:
	$a0 = { cfb44430acfd12855761726513cffe855c5ef117952c6b75616e6732e5014b7b4b13ef94433bb75fc87b7973756237135301b0f3ea14d36aff17 }

condition:
	$a0
}

        
