rule Win_Downloader_Small_4071
{
strings:
	$a0 = { 8d8500fcffff506800010000e8c900000068????????8d8500fcffff506a01e88000000083c40c8985fcfbffff6a006a00ffb5fcfbffff68????????6a00e8a90000006a01ffb5fcfbffffe8900000008d85fcf7ffff506800010000e87900000068????????8d85fcf7ffff506a01e83000000083c40c8985f8f7ffff6a006a00ffb5f8f7ffff68 }

condition:
	$a0
}

        
