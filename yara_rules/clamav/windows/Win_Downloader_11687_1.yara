rule Win_Downloader_11687_1
{
strings:
	$a0 = { 558becb9070000006a006a004975f951b868e44000e8d665ffff33c05568c8f3400064ff30648920e85b3dffff8d4de866ba0100b8dcf34000e88af0ffff }

condition:
	$a0
}

        
