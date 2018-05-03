rule Win_Worm_Autorun_415
{
strings:
	$a0 = { 558becb9240000006a006a004975f9535657b8e4484000e898f2ffff8b353061 }

condition:
	$a0
}

        
