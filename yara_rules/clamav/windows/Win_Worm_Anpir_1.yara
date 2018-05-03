rule Win_Worm_Anpir_1
{
strings:
	$a0 = { 6167e97320737572206c6520503250203a0a0d000a0d2d2d2d2d2d2d2d2d2d2d2d2d2d2d46696e2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d0a0d0a0d506f727465 }

condition:
	$a0
}

        
