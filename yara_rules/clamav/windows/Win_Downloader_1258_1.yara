rule Win_Downloader_1258_1
{
strings:
	$a0 = { ff0080f68f80e175c685c8feffff3380c5c180ee6dc685c2feffff6180c20ac685c4feffff76b2b0c685ccfeffff6c80c2d7c685c5feffff6180ce4a80cd34c685cbfeffff64c685c9feffff3280e520c685cdfeffff6c80c5b65580ed4f83ec048dbdc2feffff893c2480f2efff }

condition:
	$a0
}

        
