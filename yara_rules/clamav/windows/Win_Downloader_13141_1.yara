rule Win_Downloader_13141_1
{
strings:
	$a0 = { 20512f0f584ea21507df8f432a225f0f633224608f833a26600fa3422840e621bd1f3cefcf1f31bfbfa3551f22ef0f882e27af0fc82e40e2c35b6262e3f35b72 }

condition:
	$a0
}

        
