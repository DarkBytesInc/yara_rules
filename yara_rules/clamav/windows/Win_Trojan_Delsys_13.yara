rule Win_Trojan_Delsys_13
{
strings:
	$a0 = { 2e67657466696c652822633a5c[0-14]5c77736f636b33322e646c6c22292066312e64656c657465 }

condition:
	$a0
}

        
