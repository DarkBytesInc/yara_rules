rule Win_Trojan_Agent_35436
{
strings:
	$a0 = { 72756e6e65723d72756e6e65722663687228737472732869292d }
	$a1 = { 657865637574652072756e6e6572 }

condition:
	$a0 and $a1
}

        
