rule Win_Downloader_Small_3541
{
strings:
	$a0 = { 889b9af3999b9b1b73929f9b9b10a6c78b9b9a185f8f160fbf8f9a9b9bc9289acd1305b3919b9b644cf39f9a9b9b16dfbf8fcbf37f889b9af3bf8f9b9af3999b9b1b7354989b9b16d7bfbfca73de64646410b6c38b9b9a185f831f5b941f7c }

condition:
	$a0
}

        
