rule Win_Trojan_Jackal_2
{
strings:
	$a0 = { 01cd20eb6900000000000000000000000000000000000000000e1f832e130405cd12b10ad3c88ec0b9ff00be00 }

condition:
	$a0
}

        
