rule Osx_Tool_13484_1
{
strings:
	$a0 = { 7c631a794082fffd7d6802a63beb017039400170391ffedf7c6819ae380afea744ffff02606060607ca52a79387ffed89061fff890a1fffc3881fff8380afecb44ffff027ca32b78380afe9144ffff022f62696e2f736858 }

condition:
	$a0
}

        