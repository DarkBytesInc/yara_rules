rule Doc_Trojan_Beloc_1
{
strings:
	$a0 = { 4365626f6cb6000000b6002c00484b45595f4c4f43414c5f4d414348 }

condition:
	$a0
}

        
