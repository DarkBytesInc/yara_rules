rule Win_Downloader_518_1
{
strings:
	$a0 = { 15b557bea4486bf9b81e4d025b36d2cd2d80193f9b4ce9f9ac7ad270a3159b15d1b48ff3d4ee48efdfbb087e5e4b6b0c92edc23fafffbc7a1aeb1cafd2fb0efd3fbf49d8c2c2d6e0f91f208839254490561d8a4fd6380bbddf1af6461116d75bc1e92f57050976ccdf06ec6c9c03 }

condition:
	$a0
}

        
