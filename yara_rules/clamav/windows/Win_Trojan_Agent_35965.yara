rule Win_Trojan_Agent_35965
{
strings:
	$a0 = { 558bec81ec9c000000e81a070000000000000000000000000000000000000000 }

condition:
	$a0
}

        
