rule Win_Trojan_VGEN_302
{
strings:
	$a0 = { ed030133db8edb813e1504585874568cc8488ed8803e00005a754ab8570050b802001e8edb29061304c706150458 }

condition:
	$a0
}

        
