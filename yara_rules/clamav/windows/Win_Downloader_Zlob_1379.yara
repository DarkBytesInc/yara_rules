rule Win_Downloader_Zlob_1379
{
strings:
	$a0 = { 596aff8945fc33db538d45f8506a02ff155c60001083f8018b35fc600010751e5368192a0010e8211700008bf8688813000057e83417000083c41057ffd68b7d0853ff37ff1558600010ff37ffd6ff7704e8a5f0ffff8b5f0c85db59740e8bcbe8471a000053e89606000059ff7708ffd6ff75f8ffd6ff75fcffd66834640010e877160000596a00ff1554600010cc558bec81ec3003 }

condition:
	$a0
}

        