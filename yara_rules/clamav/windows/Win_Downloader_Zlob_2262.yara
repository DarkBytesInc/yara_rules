rule Win_Downloader_Zlob_2262
{
strings:
	$a0 = { 0c456d2eadfd290bd8539fd7e38380fa73d420a452f68eb2429f0eedb569410b97a43bfac978a7825599ba4a7749a91416bdd1c82ac932379e26033c230e2fb4da284815e3f73284bcf8c97a0af7bfdd93b81acd81bef16adb4b }

condition:
	$a0
}

        
