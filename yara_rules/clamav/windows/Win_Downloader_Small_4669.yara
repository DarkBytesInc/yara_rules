rule Win_Downloader_Small_4669
{
strings:
	$a0 = { 69616c676f6f64732e696e666f2f696e6465782e7068703f71713d5370797761726526 }

condition:
	$a0
}

        
