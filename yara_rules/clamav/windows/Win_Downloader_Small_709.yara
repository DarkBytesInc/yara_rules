rule Win_Downloader_Small_709
{
strings:
	$a0 = { 65722e6578650000000000000000000000000000000000000000000000000000000000000000006a006a00680510400068211040006a00e82a0000006a016a006a00680510400068001040006a00e80d0000006a00e800000000ff2500204000ff2508204000ff25102040 }

condition:
	$a0
}

        