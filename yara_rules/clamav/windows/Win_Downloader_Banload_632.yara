rule Win_Downloader_Banload_632
{
strings:
	$a0 = { d319658c719ce10bebb53fce9b037db0830e8f7564f4c49082b3d27e350de4d457fbf5cc1efb5ae78abf12f38a37e4a2677d4ae83f3222cdd2c3b02ebad6d95998ee39b750ad121d175dc620aeae970cc5f472f29ba54e7cbe05a900abcb3ba17348b93b2a465d02f4ea09d8ae6ab4592dceae9a3ec5 }

condition:
	$a0
}

        
