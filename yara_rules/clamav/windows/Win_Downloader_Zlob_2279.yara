rule Win_Downloader_Zlob_2279
{
strings:
	$a0 = { 6ac5ae43e7aaff68fb7da80b4a0dab945769d052e1f27ce98fb35abdcb7a26c3e8444f639f7cc01a3fb3e74d3f41939ef40701bdcec04ab7eb206f4db259073a4fb8dc85d6d09777e6afb8e76db7f156a20a5459b9a9fe509ec8 }

condition:
	$a0
}

        
