rule Win_Trojan_Bancos_2061
{
strings:
	$a0 = { a200dfe2ad75f83bc227ce9971945ae869d4289348c996c431d55ecb8ba07dd08556150cc0d102f8ba4af883305109e16b7fa6ca53f6f0eeef4bf337f00f05ea35c62848271d718750c97bcafba4 }

condition:
	$a0
}

        
