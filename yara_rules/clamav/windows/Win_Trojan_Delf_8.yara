rule Win_Trojan_Delf_8
{
strings:
	$a0 = { 4e4f54494345204252304b4552203a0156455253494f4e20734654505f426f74 }

condition:
	$a0
}

        
