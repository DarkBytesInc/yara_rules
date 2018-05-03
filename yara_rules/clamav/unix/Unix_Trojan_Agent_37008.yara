rule Unix_Trojan_Agent_37008
{
strings:
	$a0 = { 2f746d702f62696c6c2e6c6f636b }
	$a1 = { 3133435061636b657441747461636b }

condition:
	$a0 and $a1
}

        
