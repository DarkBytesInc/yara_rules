rule Win_Downloader_Dadobra_225
{
strings:
	$a0 = { e52364a28d4280c1f2fab6e7007bbd02ba74ae98f0e3c69d2bb39d0bfb9a13ae6b8534d57e44bd6157c9920eb87c627e2f0eada761a17f1699cc99d653ab0b29424a7adb95a4d7f07eb4d765ace1ca6be7222ab47204472ad0fc }

condition:
	$a0
}

        
