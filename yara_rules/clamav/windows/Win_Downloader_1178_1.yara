rule Win_Downloader_1178_1
{
strings:
	$a0 = { 3d278405da8001de309ce2ea24786d075ab16bd458de83558562e907760c3ecd136cd907e007fcaff86e7c2e1feff50eacf8ee985daef818831a78ce44ab7da885c0912bdbedabb9b17d6eb4a4f8f1d220ab54a5f868fb5c1ae41ba6 }

condition:
	$a0
}

        
