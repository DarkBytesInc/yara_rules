rule Win_Trojan_VB_1627
{
strings:
	$a0 = { 72617379790075746f6d617469000000005000000095a477dc2e2b084d9f76536d }

condition:
	$a0
}

        
