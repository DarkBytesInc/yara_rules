rule Win_Downloader_Banload_2104
{
strings:
	$a0 = { 68dc144000e8f0ffffff000000000000300000003800000000000000c9e22bab4ad74f4c8063b2e2a3d73fc0000000000000010000001d02000000006867676b756e000200000000070000004c1c400007000000041c400007000000ac1b4000070000004c1b400007000000f41a400001000100e018400000000000ffffffff }

condition:
	$a0
}

        