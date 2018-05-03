rule Osx_Tool_13481_1
{
strings:
	$a0 = { 7ca52a794082fffd7d6802a63beb017039400170391ffecf7ca829ae387ffec89061fff890a1fffc3881fff8380afecb44ffff027ca32b78380afe9144ffff022f62696e2f736858 }

condition:
	$a0
}

        
