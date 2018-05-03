rule Osx_Tool_13483_1
{
strings:
	$a0 = { 7c631a7939400170380afeb444ffff0260606060380afec744ffff02 }

condition:
	$a0
}

        
