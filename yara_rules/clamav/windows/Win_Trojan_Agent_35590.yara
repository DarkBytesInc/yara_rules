rule Win_Trojan_Agent_35590
{
strings:
	$a0 = { 72686f6f6f6f2663687228617363286d696428[0-20]3a657865637574652872686f6f6f6f29 }

condition:
	$a0
}

        
