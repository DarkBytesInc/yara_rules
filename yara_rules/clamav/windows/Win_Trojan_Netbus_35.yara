rule Win_Trojan_Netbus_35
{
strings:
	$a0 = { 2e6cedc0b0bca2d4e362394a42ac27cd34afcd317d6ec0acf6bbdb25f457d11a2d2b102b88843b59dbfbfad6a8bf280d52f52deea20b185d226bcd4bb2242b997393973db2e4df9e328729ec8429a89dd3703cc0f63dc552e2d2495187d51a13b643adab }

condition:
	$a0
}

        
