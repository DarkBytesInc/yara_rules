rule Win_Downloader_1241_1
{
strings:
	$a0 = { 5effffff66c68540ffffff4cc68566ffffff37c68570ffffff6f80ea16c68548ffffff3480f15fc6854affffff3880ee3980ee8ec68571ffffff6380eeefc68553ffffff2d80eafdc68543ffffff4480f1c6c68556ffffff6280cd44c68552ffffff3280e22fc68565ffffff31b1 }

condition:
	$a0
}

        
