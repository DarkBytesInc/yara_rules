rule Win_Trojan_Fakeav_23
{
strings:
	$a0 = { 558bec6aff687b21001468591e001464a10000000050648925 }
	$a1 = { 6e657473656375726974797765622e636f6d3230 }

condition:
	$a0 and $a1
}

        
