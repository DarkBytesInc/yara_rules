rule Win_Downloader_Zlob_2036
{
strings:
	$a0 = { 3769cdcd4f6df8014d59bfc7e47ab5bff043bc5078ecc5ab16fc43b42fc711cc6970b43d1ceaa8e68d4d0a7e6418b9e7316ebddbefc10ac2d3a8083af034bd0b7820fac083e13c323a52c0ad69f194236aad61f8cf8437c5e1e178e4e0003b70ddc8f9ac }

condition:
	$a0
}

        
