rule Win_Downloader_2708_1
{
strings:
	$a0 = { 1570664000e8caf3ffffa174664000e83cfdffff84c0742468786640006a006a0068984040006a006a00e8fdf9ffff6af1a17866400050e838faffff33c05a59596489106821434000c3e915ecffffebf8e80af1ffff0000ffffffff0a0000005c646c6f61642e696e6900000000000000000000000000000000000000000000 }

condition:
	$a0
}

        