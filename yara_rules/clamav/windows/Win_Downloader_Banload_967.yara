rule Win_Downloader_Banload_967
{
strings:
	$a0 = { 03d6cf9cb9128090e1084fe55f7a7297c8ba581e5a59d19c480429e7578b4c848d8ba4bcd433a1cdcc54cd9c3236df5940dca3b9c5e4a6d5f6724ed7d83a97f3d3c0f2cfa5d37c82482cd33a06c486f0a83da81a55d97e3514b7680a2a605bba5ee83faa58eb079031eafd156f1e }

condition:
	$a0
}

        
