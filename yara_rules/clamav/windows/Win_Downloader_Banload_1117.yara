rule Win_Downloader_Banload_1117
{
strings:
	$a0 = { 3ce77eb32438cba98eda4ebcf36cab784ce4051266051bc8f8448820ee1ba7762c4556258eae04c5b8c488baae3139bba0b6d86d9cd537b8cf4580693f88f2eb9ff7f7d1125d81f82877c7919640d527c882 }

condition:
	$a0
}

        
