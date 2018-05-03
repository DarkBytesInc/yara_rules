rule Email_Trojan_Trojan_558
{
strings:
	$a0 = { 466564657820547261636b696e67204e2a33353738393939383939 }

condition:
	$a0
}

        
