rule Win_Downloader_Zlob_1679
{
strings:
	$a0 = { fab2b97af4b76c529f9af2906a53b9af4dd2ed8e48e01f44de34492c898abe74880d755fb968c2eb4a785c51cbe21d5aaddc92b9cb78c30ce2e889ddfc3ee2d9855a1a2576ed4a2106b6eaeecd5744180ad5994e275998e5c7c7 }

condition:
	$a0
}

        
