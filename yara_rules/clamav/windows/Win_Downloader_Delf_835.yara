rule Win_Downloader_Delf_835
{
strings:
	$a0 = { ff08000000637372732e73637200000000ffffffff0a00000063617274616f2e6578650000ffffffff150000004153502e4e }

condition:
	$a0
}

        
