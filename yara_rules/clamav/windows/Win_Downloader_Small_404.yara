rule Win_Downloader_Small_404
{
strings:
	$a0 = { 7263682e63632f782f646c2e7068700000000000000000000000000023450000005c72656773767233322e657865202d73200000005c77696e33326170702e646c6c00000020402d }

condition:
	$a0
}

        