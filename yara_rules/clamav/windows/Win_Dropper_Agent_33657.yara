rule Win_Dropper_Agent_33657
{
strings:
	$a0 = { 6ff2e3a6dff78f2090437aac3985a491bb8655f8c839e82318919df7047646c46b3ac42b0a0ec376d78e986746fc49d532c4c2e31c3178e2d8e678ebb21ddf79de3e6a1ca52e78f87ba4f7c8a276db22 }

condition:
	$a0
}

        
