rule Win_Downloader_1094_1
{
strings:
	$a0 = { 862f0c4e651891eafb2114db219826eedf4be4ced68c334a056c862c0abe3d4e44a183bdbaa21fe183e2dd1423dee6e9b5d098b10017e9e429cf850d1028cda86021f6edc68a1ea2452326ab1c9cf410f033be1f171bd8462ed047b0 }

condition:
	$a0
}

        
