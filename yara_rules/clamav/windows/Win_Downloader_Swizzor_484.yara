rule Win_Downloader_Swizzor_484
{
strings:
	$a0 = { f5b2da557729d16d10380c0eaf0d74ce08a080ac086f6772493a1f072b7514b4cee482ed90c8fb25b4512d8e53bdb13dcf3ca88bde71580870d0a3473c83e6b39dea59e70b909050479956e4e36f }

condition:
	$a0
}

        
