rule Win_Trojan_Bancos_770
{
strings:
	$a0 = { 05d32c2acdf8e1bbba85bfc365ad31e954d43eedefa8cebe1132944b190290b526150f749e5e1494438c7df34c8f2ca15bf4deafb6681a74ab0c5a305f60a254fe5f11030f887f9dd95718cc5bc4fecd6980e62dd15efacdfb1b44538d15cc92300949205ec12f949f31d1bce0e6 }

condition:
	$a0
}

        
