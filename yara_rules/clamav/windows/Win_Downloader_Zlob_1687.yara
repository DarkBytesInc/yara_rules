rule Win_Downloader_Zlob_1687
{
strings:
	$a0 = { bcd0e2200a385f8f0dd7ff4d8e23ea856270ac8b32d2d7b2c0c301008cecb9abcf9904a0b176a701d62235df7b888d0fce5640dd351062547b67c5fe09f41c2da4488edf20bac28abc92fb30bd7b5997eb9551d29550654ab691 }

condition:
	$a0
}

        
