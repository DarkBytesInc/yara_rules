rule Win_Downloader_67_3
{
strings:
	$a0 = { e0af77cd56428d9fbc92dce97f2a33d6bca1efe9066007f358ef65f7437cdf74f86fc6e894bfba4d1e21d4866a4d61614cb2b40c99966b6d0fbac87504b4fd9d71b298027290337e6756e10cc7bbbd0619982e245ae7c37f9e }

condition:
	$a0
}

        
