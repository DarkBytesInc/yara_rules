rule Win_Downloader_871_1
{
strings:
	$a0 = { 3373a720df20c04f3df91faceba60dc21c9b8e1e975d4b9edd36a7474a298fa5d96e88d2528e61ee69a89a40dcf01da45722db77f889ad12dce4d798b6e9762abdb33a76e3dbf5a4112c1bd6a28ad365328fc0f22260b65c03ecb61cd5079a0fdd9aee7a }

condition:
	$a0
}

        
