rule Win_Downloader_Zlob_1527
{
strings:
	$a0 = { 55307825cd130016fb98343de7fa3bea7a8b51c364143054281feea69ea5ca6d6d4392283b5b18f35a4e7a327a656846978eb5bc82db0e16b8c1fb67fe54ab358a5ff847a8b55f3b0387ed017cb730650dfb }

condition:
	$a0
}

        
