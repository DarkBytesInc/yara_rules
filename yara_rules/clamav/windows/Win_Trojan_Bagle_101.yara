rule Win_Trojan_Bagle_101
{
strings:
	$a0 = { dbcdba292307ed6871df752810ed0529a50d2afc48ff2e8500e80fbb1fcdcbc079562c18a0cf294d74820c211882333eba51b8f5532ba90924e64ce5fbc5d88a1dac6af527ef2810fb631e50e2d8cd23ab2aa7a3c76617daa5afe4723fb86cd4 }

condition:
	$a0
}

        
