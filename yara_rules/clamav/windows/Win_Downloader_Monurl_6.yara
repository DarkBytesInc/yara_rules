rule Win_Downloader_Monurl_6
{
strings:
	$a0 = { 687474703a2f2f }
	$a1 = { 75726c002e00646c6c006d6f6e0046696c6500446f776e6c6f616400410055524c00546f0000000000000000 }

condition:
	$a0 and $a1
}

        
