rule Win_Downloader_Delf_834
{
strings:
	$a0 = { 558becb9040000006a006a004975f951b8fc7e4000e832c5ffff33c055686580400064ff3064892068fe00000068a8a74000e8??c6ffff }

condition:
	$a0
}

        
