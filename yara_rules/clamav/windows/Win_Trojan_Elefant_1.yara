rule Win_Trojan_Elefant_1
{
strings:
	$a0 = { 8d45f0bab0b54500e85395faff8d45fcb9c8b545008b55f0e88795faff8d9500fcffff33c0e88a75faff8b9500fcffff8d45f8b9c8b54500e86795faff6a008d45fce86197faff508d45f8e85897faff50e82ab7faffb201a11ca44500 }

condition:
	$a0
}

        
