rule Win_Downloader_Delf_962
{
strings:
	$a0 = { 9279d606cf4eb9d71614c7efa8a8e27f50095eb60644357e27a17e961d5b64783192e92bd3d7ae3a824846afeb812e97e687c2f60d03cea9dea39214be246b537415d115fdb1 }

condition:
	$a0
}

        
