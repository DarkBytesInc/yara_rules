rule Win_Downloader_Small_1675
{
strings:
	$a0 = { 56be00500010e8180a0000be40500010e80e0a0000be70500010e8040a0000be80500010e8fa090000be88500010e8f0090000be94500010e8e6090000bea0500010e8dc090000beb0500010e8d2090000bebc500010e8c8090000bec8500010 }

condition:
	$a0
}

        