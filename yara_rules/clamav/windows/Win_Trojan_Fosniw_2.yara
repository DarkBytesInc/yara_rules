rule Win_Trojan_Fosniw_2
{
strings:
	$a0 = { 272541505049442527203d2073202749454b6579776f72645f45584527 }

condition:
	$a0
}

        
