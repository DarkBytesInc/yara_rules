rule Win_Worm_Krepper_33
{
strings:
	$a0 = { 8d45f8baf8784000e893c4ffff8d45f0ba0c794000e886c4ffff8d45ecba2c794000e879c4ffff8d45e8ba94794000e86cc4ffffe92f0200008d45f8bacc794000e85ac4ffff8d45f0bae4794000e84dc4ffff8d45ecba047a4000e840c4ffff8d45e8ba8c7a4000e833c4ffffe9f6010000 }

condition:
	$a0
}

        
