rule Win_Downloader_Small_967
{
strings:
	$a0 = { 8b45e8e8eef9ffff506a00e852feffff6a018d55e4b86c354000e883feffff8b45e4e8cff9ffff50e885fdffff33c05a595964891068293540008d45e4ba03000000e8f7f8ffffc3e969f3ffffebebe8d6f7ffff0000ffffffff2a000000707c7c7842373769 }

condition:
	$a0
}

        
