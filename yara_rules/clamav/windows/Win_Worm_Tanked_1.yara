rule Win_Worm_Tanked_1
{
strings:
	$a0 = { 5f7600ba1db3f3a380a91eea19082348a20267fd30b1a9cc633c010b10cd23d8a8ad33009d2f548991d723b2487e00c08c6ef0020389c311f7730748e4012bc8 }

condition:
	$a0
}

        
