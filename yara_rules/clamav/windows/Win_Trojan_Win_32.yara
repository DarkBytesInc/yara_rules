rule Win_Trojan_Win_32
{
strings:
	$a0 = { 4a544d202d2066726f6d20655b61785d20746f20486f6d6572205468612050696c65 }

condition:
	$a0
}

        
