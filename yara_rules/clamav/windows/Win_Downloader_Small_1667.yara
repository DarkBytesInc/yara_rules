rule Win_Downloader_Small_1667
{
strings:
	$a0 = { e67a3b612f73197065748564ec7935652e72663e3f7a1e3a5c62bd9f742e8a6c644bc67702c5646f6242ca61636985a1641ec20d71759a }

condition:
	$a0
}

        
