rule Win_Downloader_71_2
{
strings:
	$a0 = { 97e0f7f8d1d38bf6318ebc1599fd1b625d13724d723b2f853983fd2c526caf12a896328c8a9e1ac1d81c74ed11ca86d73ac46b6755a3ca71bd572b4cbfb29bd19527fc8b126ef1d5137b4af8eb40fbc818a95e68441f24fa6ea4e67f5c8ecca94c9ca1a1b3f67ced20fd66ddbfe31caf1e4b939d55162aa7 }

condition:
	$a0
}

        
