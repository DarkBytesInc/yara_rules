rule Doc_Trojan_Aos_2
{
strings:
	$a0 = { 7373776f7264203d2022416e676c655f4f665f53696e22202620612026206220262063 }

condition:
	$a0
}

        
