rule Win_Trojan_VB_1597
{
strings:
	$a0 = { 614c851fb23ab3a87a5a0000000000000100000000000000000050726f74656e73 }

condition:
	$a0
}

        
