rule Win_Downloader_Small_3001
{
strings:
	$a0 = { e7064eafd437e7fb4232ce934ed40bfcc56bef46a523da8abc7fb1758968e67235ba3ab8454214f9e2cee9ba0b4bd5ab0d4ae31f670d5c3b3db0b02b4c7dd1125a342d585b286dca8fcf37b5290f79fba7036cbddb4a71a13d17ecc1eb2728e8c2a9be877ac9ad5473342f4bed8f0d6b91f6 }

condition:
	$a0
}

        
