rule Win_Downloader_Banload_267
{
strings:
	$a0 = { de0c87802a1489e410868f4f3f6f9c8ce3e87381e62b6b7bc1a074ea1e60d38c1596239caeef32648c6808fe30205c3437d44af0f9b9aa29990b904d6fc78eb92c3bed5548bcffccddb09b35e3b2a6f93c2726cb37ea56084373 }

condition:
	$a0
}

        
