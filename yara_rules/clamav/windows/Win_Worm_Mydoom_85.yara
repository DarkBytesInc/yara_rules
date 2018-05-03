rule Win_Worm_Mydoom_85
{
strings:
	$a0 = { 558becb9060000006a006a004975f951535657b8e8 }
	$a1 = { 5053755442454243444f454045444245202d3d4f4549 }

condition:
	$a0 and $a1
}

        
