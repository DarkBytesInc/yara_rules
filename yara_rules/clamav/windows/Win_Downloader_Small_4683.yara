rule Win_Downloader_Small_4683
{
strings:
	$a0 = { 104000e8bfffffff83e00383c008782156578d4dd48d7001e8aaffffff6a1a995ff7ff80c2418811414ec6010075e95f5e8b450c6a035999f7f98d45d4ff7495f45068 }

condition:
	$a0
}

        
