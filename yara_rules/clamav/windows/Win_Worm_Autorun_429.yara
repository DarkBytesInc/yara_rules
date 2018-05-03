rule Win_Worm_Autorun_429
{
strings:
	$a0 = { 5789e781c7040000005653bb8448004881cb385a2c7281c3514d4a6281e30e42 }

condition:
	$a0
}

        
