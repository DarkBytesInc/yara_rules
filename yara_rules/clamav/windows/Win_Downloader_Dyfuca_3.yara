rule Win_Downloader_Dyfuca_3
{
strings:
	$a0 = { a659e8d8c8b80fb0ee7f90a6a4984459465543415f534973ff96e4600b454e074f5054494d495ac0dec0fe45525f43524d000f320f566f17f2454e4b034e454c }

condition:
	$a0
}

        
