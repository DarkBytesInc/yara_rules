rule Win_Downloader_Delf_126
{
strings:
	$a0 = { 696d652e636f6d2f6d696e64732f6d6f6e657973706a2e65786500ffffffff0c0000006d6f6e657973706a2e6578650000000053 }

condition:
	$a0
}

        
