rule Win_Trojan_Vundo_500
{
strings:
	$a0 = { 6a28681c????10e849ffffff33ff57e8190000006681384d5ac3000000000000000000000000000000 }

condition:
	$a0
}

        
