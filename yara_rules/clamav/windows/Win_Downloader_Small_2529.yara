rule Win_Downloader_Small_2529
{
strings:
	$a0 = { e581ec9400000081ecfc0c000080e63589e380cd678925c84d4000a1486040008983500a0000a14c6040008983e80100 }

condition:
	$a0
}

        