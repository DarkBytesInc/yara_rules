rule Win_Worm_AG_1
{
strings:
	$a0 = { b25a0d8775e59a73c05ad6499a625fbfeec49f2dc6f58b1dc50cef87010da3c9219d99f4ba51ee543a5adef87018419421fef34060a16456cc534ebd6684df15cf3ed45b414a5d22d969b96fa26608 }

condition:
	$a0
}

        
