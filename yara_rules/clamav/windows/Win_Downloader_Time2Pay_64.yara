rule Win_Downloader_Time2Pay_64
{
strings:
	$a0 = { fe0dc7ff0a870365dfd83275faed2269e9d83765be4bafff62ebdb74bfb5078b613e99ffae7d63d26d13a7d1d4c945809f8fa8137142df0dddaf6bd1ed560f5e5ee8dbec1c51ec05d12b8bf662ebdd4557ea63dbd3340dfc59b4200350c19ecded043ccfeb6d12d1aa6f83aec493e78282693cd5f16b870324d0c6 }

condition:
	$a0
}

        
