rule Win_Downloader_Zlob_1718
{
strings:
	$a0 = { fe993b1bb39d4bfd8507e7969b073bb9f0052d5641b8c5392612b63a0de704c83c5aa38a632255f67b6a67ca62f0ef75007ea634227ea26c3fe3a71a48a2eeb4458d443b83db931edddf36c44ce42dc09ea315068ecc96f46e36 }

condition:
	$a0
}

        
