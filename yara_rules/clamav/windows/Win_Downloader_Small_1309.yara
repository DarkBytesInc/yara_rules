rule Win_Downloader_Small_1309
{
strings:
	$a0 = { 0c45442666526df273fa61efcc5f70ea673d65263b79f5a510b83e5c3f7938309e322e9a7818120b3f5045534d96771ce45c4da5a43d1d496e3ffbe9cfc82045781b70 }

condition:
	$a0
}

        
