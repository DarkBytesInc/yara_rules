rule Win_Downloader_Banload_460
{
strings:
	$a0 = { b7b7f44ac69d7335e975eb9e00b9875d3047a0a5cfce0e5519e89ba04d02329b5abf784b334f24626f9ad749b738624a11c64c5d2e236ff31e143ee92fd6fa624f687a46211c0fbf6d687d7d000bc03bd381ae69 }

condition:
	$a0
}

        
