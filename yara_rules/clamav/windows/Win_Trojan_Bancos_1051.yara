rule Win_Trojan_Bancos_1051
{
strings:
	$a0 = { c187332b650b9d81f336f9589dd59e49d4c09c5b6a8a5f762544a6a91204d7fe52aab05a9b0a1db3769380cc80e8bcce7bb3d5bc1aee66de7ff3611cc28920d9eeb8ca5d79eb6440e7b19c2734554fa89aa19d785bde6f69 }

condition:
	$a0
}

        
