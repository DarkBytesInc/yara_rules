rule Win_Trojan_Agent_35576
{
strings:
	$a0 = { 9c60e8000000005d83ed078d8d6ffcffff8039010f8442020000c6 }
	$a1 = { 44643334382e6578652e65786502323734343332 }

condition:
	$a0 and $a1
}

        
