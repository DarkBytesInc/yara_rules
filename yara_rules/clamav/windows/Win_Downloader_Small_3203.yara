rule Win_Downloader_Small_3203
{
strings:
	$a0 = { fce59b2f2180f1481c85932fa1e5f44dc28942d37c736b3658fc6d10f6b247685a3a6fd964f0f3787da051a7662153c6a3e5932f602756e39b505e1a2dbded23f4e5145315e9 }

condition:
	$a0
}

        
