rule Win_Downloader_59911_1
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085f67509833d0001222800eb2683fe01740583fe027522a1 }

condition:
	$a0
}

        
