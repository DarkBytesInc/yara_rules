rule Win_Trojan_VGEN_654
{
strings:
	$a0 = { 023db90000ba4201cd218bd87209b8024233c933d2cd21c3434150545552452e43415000b43ecd21c38b0e8d012b0e }

condition:
	$a0
}

        
