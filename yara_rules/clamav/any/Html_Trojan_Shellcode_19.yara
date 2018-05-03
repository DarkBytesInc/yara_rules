rule Html_Trojan_Shellcode_19
{
strings:
	$a0 = { 756e657363617065 }
	$a1 = { 2575????65382575303030302575 }

condition:
	$a0 and $a1
}

        
