rule Win_Downloader_Wallon_2
{
strings:
	$a0 = { 55a731e1e4d7c0e6ab31a3285307bcaac3c51a4bb71adaab4ef4c7b27bee2df3fc8eebc1dc7eb99ae631bfb4f6b6ed22e09f303db0bacc6ea9fbd11b49aff7c92b71702f7140b47b27a571bf3a1a151304b02e02c8124f2103b395579178ec653060 }

condition:
	$a0
}

        
