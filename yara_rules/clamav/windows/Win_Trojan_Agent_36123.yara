rule Win_Trojan_Agent_36123
{
strings:
	$a0 = { b800??0101ffe000000000000000000000000000000000000000000000000000 }

condition:
	$a0
}

        
