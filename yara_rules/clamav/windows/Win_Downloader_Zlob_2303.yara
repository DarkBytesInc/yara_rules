rule Win_Downloader_Zlob_2303
{
strings:
	$a0 = { 24f670d5d825dc8ab45bc6069f23a613c63f9ef736c57dbcfea6771156544a899ab9acb8cea08fc8dfafcac759d7e713e74fd8a8af2ba1223002c9fb03f1e67bef5cc7455dac9da4691d81961de7523f3ecb584b463bb9909a0b }

condition:
	$a0
}

        
