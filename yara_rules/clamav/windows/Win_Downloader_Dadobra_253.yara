rule Win_Downloader_Dadobra_253
{
strings:
	$a0 = { a3625eb62135c06a5ff16185f2531e3c86e76c5fb10522caf7e3d3d1e331dc82a7a284421ac6b4c4bd3cb9ab42bc6a0e0366a5d031a1ca1333b62f35fa01dc0a76c838da87c31e4ced919c9d95ff1835112443928f }

condition:
	$a0
}

        
