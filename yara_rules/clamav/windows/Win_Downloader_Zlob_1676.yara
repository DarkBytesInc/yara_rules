rule Win_Downloader_Zlob_1676
{
strings:
	$a0 = { cc53b8e9a7a6d4d84d1105c79b9c47cfddbc033c9f8b1e68a7f63ad3e8db2a4567e9bbe7b634a937375969fb52a9ea9d67778ccf2d99cb4011084493261b9f945c1ebcba2e329f4b6558ed6eee01a029d59f8c29985e966a1e51 }

condition:
	$a0
}

        
