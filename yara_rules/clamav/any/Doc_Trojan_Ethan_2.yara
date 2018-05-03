rule Doc_Trojan_Ethan_2
{
strings:
	$a0 = { 734e616d65203d2022633a5c65766f6c76652e746d7022 }
	$a1 = { 2e4b657977726473203d2022457468616e223a }

condition:
	$a0 and $a1
}

        
