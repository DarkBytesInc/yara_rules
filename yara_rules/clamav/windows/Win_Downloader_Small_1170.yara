rule Win_Downloader_Small_1170
{
strings:
	$a0 = { df7020babb2cbf29fa29b4c555d54ab0c2665f4af0665bb1aed016abae6b7e2156a20b8513680a0b692a184f537475625061746800020061306963696b6f2e }

condition:
	$a0
}

        
