rule Win_Trojan_Agent_34640
{
strings:
	$a0 = { 53797374656d32342e657865 }
	$a1 = { 1d5c006e006f0072006a00340035007300790073002e006500780065 }

condition:
	$a0 and $a1
}

        
