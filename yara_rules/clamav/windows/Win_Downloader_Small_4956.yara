rule Win_Downloader_Small_4956
{
strings:
	$a0 = { 4331215f9025c8276419325f190d5cc085f411a4fc2281e8f88fa90c8d0c43e9089986437b21a595a72421b188e31244bd32c7a418c9322fa430d5321319e10cd386221eec2845ab842158c710c3283b18ec57e8384f8f8368a0e115233e20d87084125a }

condition:
	$a0
}

        