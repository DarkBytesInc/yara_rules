rule Win_Downloader_Small_1289
{
strings:
	$a0 = { bffb2e6a706730633a5c6d7333322e7379730055172d4167656bff7fff6e743a2025730d0a504d6963726f736f66742049 }

condition:
	$a0
}

        
