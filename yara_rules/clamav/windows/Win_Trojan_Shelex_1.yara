rule Win_Trojan_Shelex_1
{
strings:
	$a0 = { e381262afce50ea5b3e44d3e9ea15db233d94055ab1e3212eca1ac33a06d2a9dac0d87a1dea67e0e278a64676d5af88602a7af7826e8958482744bb88b326e80b6c7859dff90e304408fc2862860c6f0fb02d887d0ce }

condition:
	$a0
}

        
