rule Win_Trojan_Agent_36733
{
strings:
	$a0 = { 5504031412424f4f4d20434f4d4d554e49434154494f4e30820122300d06092a8648 }

condition:
	$a0
}

        
