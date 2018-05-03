rule Unix_Trojan_Zollard_1
{
strings:
	$a0 = { 557365722d4167656e743a205a6f6c6c617264 }

condition:
	$a0
}

        
