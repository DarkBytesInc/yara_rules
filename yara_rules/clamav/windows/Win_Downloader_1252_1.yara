rule Win_Downloader_1252_1
{
strings:
	$a0 = { ee93c6857effffff6180e6c180e2475583ec088b85d7fdffff89042480f6668dbd77ffffff897c2404ff15685201105d80eebe898575fcffff8b8575fcffffa30c740110c68519fbffff56c68514fbffff65c68510fbffff52c6851cfbffff7580e68080c670c6851ffbffff0080 }

condition:
	$a0
}

        
