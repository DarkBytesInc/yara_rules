rule Win_Trojan_VGEN_772
{
strings:
	$a0 = { 2ccd21803e030100740580fe1e7f0980fa0074eb88160301c606ff0700c606000804c606090800b92700ba1501b44e }

condition:
	$a0
}

        
