rule Win_Trojan_Trivial_345
{
strings:
	$a0 = { 05dc002ddc00ba3f0181f19b0081f19b00cd217227b8023dba9e00cd21b740b14580c11780e917ba000193352500352500cd21b43ecd21b44febcb90c3 }

condition:
	$a0
}

        
