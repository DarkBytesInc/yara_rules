rule Win_Downloader_Klezer_1
{
strings:
	$a0 = { 3036323200000000000000000000000000000000000000b00000000000000002000000010000007099b29c2a49504c8006f3b499c5fc2801000000c0000000d0000000010000000000000001200000000000000000000000000000736176616765726f }

condition:
	$a0
}

        