rule Win_Trojan_SubPub_1
{
strings:
	$a0 = { 4163636570742d456e636f64696e673a206261736536342c677a6970 }
	$a1 = { 2f746d702f73637265656e2e6a706567 }

condition:
	$a0 and $a1
}

        
