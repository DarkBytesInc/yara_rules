rule Osx_Tool_13479_1
{
strings:
	$a0 = { 7ca52a794082fffd7d6802a63beb017139400171391ffece7ca829ae387ffec79061fff890a1fffc3881fff8380afeca44ffff0260606060380afe9044ffff022f62696e2f736854 }

condition:
	$a0
}

        
