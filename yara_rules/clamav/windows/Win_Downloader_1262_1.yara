rule Win_Downloader_1262_1
{
strings:
	$a0 = { 8b45b0f7e18945b08b45b08985e2feffff31c080e17f80ea4531d2b17480f1c831c9b9140000008b85e2fefffff7f18985e2feffff8d75bc8b85e2feffff01068d7dbc8b07898592feffff80e284d1a592feffff8d75bc83c6088b8592feffff2906b16b81bd4efeffffc0000000 }

condition:
	$a0
}

        
