rule Win_Downloader_Petrolin_1
{
strings:
	$a0 = { 97e13103db0d8266067d3454a25043c303239d67141c2520f43958ed23e9326fc72540ecb04f93c8e9b8a81f0000ff9f8200687474703a2f2f3030386b2ed6fa7ffb }

condition:
	$a0
}

        
