rule Win_Trojan_SillyC_18
{
strings:
	$a0 = { e800005e8b4463a300018a4465a202011e06071f61680001c3601e06b8023dcd21723b93b43fb90300ba6702cd21b8 }

condition:
	$a0
}

        
