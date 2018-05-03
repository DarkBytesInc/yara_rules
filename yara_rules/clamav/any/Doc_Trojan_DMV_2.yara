rule Doc_Trojan_DMV_2
{
strings:
	$a0 = { 7469746c6524203d20224d57534320436c617373204f662027393622 }
	$a1 = { 70726573656e74203d2031 }

condition:
	$a0 and $a1
}

        
