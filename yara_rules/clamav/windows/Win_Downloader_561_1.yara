rule Win_Downloader_561_1
{
strings:
	$a0 = { 8547ffffffb26480e1388b459b298547ffffff83bd47ffffff007402eb05e9080200008b45c389853fffffff80f1bec1a53fffffff028b857fffffff8985cafeffff80ea348b459b2985cafeffff8b85cafeffff89854bffffff83854bffffff015583ec0880cde1c704240000000080e6cd8b854bff }

condition:
	$a0
}

        
