rule Win_Trojan_Agent_37037
{
strings:
	$a0 = { 466575735f596561685f4d6163655f47696c745f506169645f496f74615f526f65736f77 }

condition:
	$a0
}

        
