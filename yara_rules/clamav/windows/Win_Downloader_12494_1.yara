rule Win_Downloader_12494_1
{
strings:
	$a0 = { 87cb87cb569051595e519051595990bf1310400087c99087c987ff87ffbed21540009087db87d987d9 }

condition:
	$a0
}

        
