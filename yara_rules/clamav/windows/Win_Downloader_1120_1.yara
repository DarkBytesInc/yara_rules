rule Win_Downloader_1120_1
{
strings:
	$a0 = { 177c005381aee1876d83dc987562ccfa4fc8f9dd3332198b2020c811a1b1e3a30fa4a3a495f54275a145579ccd7a0ff468ad76b22d23a6b8418bb5aca36aa77b7aabfa0ee984af2fdb47161a2ee008b2e9c7b6d1a4ae0f41473b9785 }

condition:
	$a0
}

        
