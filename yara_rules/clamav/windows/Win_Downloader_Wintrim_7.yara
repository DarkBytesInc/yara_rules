rule Win_Downloader_Wintrim_7
{
strings:
	$a0 = { 797374656d2050726f766964657200000000726567656469742e657865002f732000434552545f444953504c4159454400004e4f000059455300536f6674776172655c6c69766573766300000000536f }

condition:
	$a0
}

        