rule Win_Downloader_Small_3270
{
strings:
	$a0 = { 18857f5d37080a01763868748e703a2f207a616765760e71736f69272e624fbfcf756e3f7c9c70689f3fc7643d253e11 }

condition:
	$a0
}

        
