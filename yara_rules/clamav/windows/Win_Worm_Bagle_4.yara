rule Win_Worm_Bagle_4
{
strings:
	$a0 = { 5dc39a8b9547244000e8f9000000e801000000c783c404bb737e00006a046800300000536a00ff954b244000e801000000e883c40468004000005350e801000000e983c404508d95cc24400052e80e000000e8010000006983c4045a5e0e56cb }

condition:
	$a0
}

        