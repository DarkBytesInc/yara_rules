rule Java_Trojan_Downloader_186
{
strings:
	$a0 = { 01000f4c696e654e756d6265725461626c65 }
	$a1 = { 01000c6a6176612e6e65742e55524c }
	$a2 = { 01001675726974792e50726f74656374696f6e446f6d61696e }

condition:
	$a0 and $a1 and $a2
}

        
