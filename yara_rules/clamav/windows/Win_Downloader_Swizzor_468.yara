rule Win_Downloader_Swizzor_468
{
strings:
	$a0 = { ede683fc7d2ce7fff49e2767fb0f596657090edbd1c68ca44a938aaf7ce6404a81f4a31d30e73e8b2d4fb6ac98b24512fb7723af08385c01bcb327fd254ba41c5b14cfed1072244fc5cdb2eff49f03ac1330965933710117bbea }

condition:
	$a0
}

        
