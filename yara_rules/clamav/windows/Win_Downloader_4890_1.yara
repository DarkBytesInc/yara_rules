rule Win_Downloader_4890_1
{
strings:
	$a0 = { 8d45ece8eeafffffc3e910aaffffebf05e5be8efaeffff000000bbd866d2e466b4d366c7b02e2ea1a433306636356635316635b5da35b4ceb8fcd0c20000633a5c69702e747874000000687474703a2f }

condition:
	$a0
}

        
