rule Win_Trojan_Delf_2251
{
strings:
	$a0 = { 558bec83c4ec53565733c08945ecb8d4904100e8 }
	$a1 = { 433135434333373138344646374438413935444530 }

condition:
	$a0 and $a1
}

        
