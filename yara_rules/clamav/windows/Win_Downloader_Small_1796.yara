rule Win_Downloader_Small_1796
{
strings:
	$a0 = { 11703a2fc5779f022edc64876e32317a811f74f6f41828785f11d9206e664f3d9e873a5c62af67742ee26c649c4915676f62c80f6163691b8fb78371757da4 }

condition:
	$a0
}

        