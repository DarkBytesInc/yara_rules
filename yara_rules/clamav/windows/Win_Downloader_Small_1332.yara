rule Win_Downloader_Small_1332
{
strings:
	$a0 = { 89866be0c6df7020babb2cbf29fa29b4c555d54ab0c2665f4aaed016abf0665bb1ae6b7e2156a20b8513680a0b692a184f537475625061746800020061306963 }

condition:
	$a0
}

        
