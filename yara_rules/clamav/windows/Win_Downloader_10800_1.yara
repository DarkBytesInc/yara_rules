rule Win_Downloader_10800_1
{
strings:
	$a0 = { 68??21444464ff306489208d55ecb8??214444e8dff9ffff8b55ecb840814544e88af5ffff6a006a006a026a006a016800000040a140814544e87df6ffff50e84bf9ffff }

condition:
	$a0
}

        
