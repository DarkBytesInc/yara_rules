rule Win_Spyware_Banker_3368
{
strings:
	$a0 = { c152d1121edc3c27447f749c2c1b541dacdf0503ca21b62fa91547c60ebf936ea5a5d9b32f103aa451810c419fb819d7511dadee0ffbbf47dddf769d9c3afb0aca1ea45120ddd2a5f1d8adbc17cab885b84ad57613 }

condition:
	$a0
}

        
