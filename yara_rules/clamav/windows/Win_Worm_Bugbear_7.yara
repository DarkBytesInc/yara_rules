rule Win_Worm_Bugbear_7
{
strings:
	$a0 = { c8dd006203bb01410b3e000762ae393b601b8202136a3f0bcf1de6baaa233e170bdc031b6bb6837d0bad4b7803031bc3139dbcb2995f071302e11efd06c2031a }

condition:
	$a0
}

        
