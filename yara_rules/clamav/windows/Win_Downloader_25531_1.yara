rule Win_Downloader_25531_1
{
strings:
	$a0 = { 6a00ff1530404000e80300101c50ff1550404000ccff74240433c0505050ff151c404000c3558bec518d45fc5033c050ff750cff75085050ff157c404000c9c3 }

condition:
	$a0
}

        