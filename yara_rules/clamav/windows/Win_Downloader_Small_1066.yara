rule Win_Downloader_Small_1066
{
strings:
	$a0 = { 11400064ff3064892033c05a59596489106832114000c3e958ffffffebf85dc3030000003c114000cc1040009c10400004114000d4104000000000000c114000558bec83c4f0b834114000e8e0feffff6a006a0068a811400068b41140006a0068d8114000a1142040008b0050e882feffffffd06a0568a811400068ec114000a1102040008b0050e867feffffffd0e8e4feffff633a }

condition:
	$a0
}

        