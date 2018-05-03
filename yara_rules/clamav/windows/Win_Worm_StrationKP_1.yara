rule Win_Worm_StrationKP_1
{
strings:
	$a0 = { 34251c3e35243d3417383d341f303c3410510094a9b8a581a3beb2b4a2a2d100000000615e5757 }

condition:
	$a0
}

        
