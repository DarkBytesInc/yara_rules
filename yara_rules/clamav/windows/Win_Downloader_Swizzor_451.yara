rule Win_Downloader_Swizzor_451
{
strings:
	$a0 = { feb6fd702b83536f8e54ebc3d82cf893ebdb535f38ae4a6bde243b5d2110e2f9643445208dfa627a3565e48ce90c6eee06ae61a988f1582f56cd2ef670d1877162db871a7ed93e1c6ea09100bcb30b66fda02203946b70aa92a4 }

condition:
	$a0
}

        
