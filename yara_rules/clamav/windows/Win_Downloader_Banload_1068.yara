rule Win_Downloader_Banload_1068
{
strings:
	$a0 = { bc4d60d087f4da71950d520aab070078fa38057fd7d696a72294b1b37960a695bf8be15822126f2be69c0bbef08d27ede8b32179d660efe33d0bed949119836ca818f6ed004c066c21b9303866f5 }

condition:
	$a0
}

        
