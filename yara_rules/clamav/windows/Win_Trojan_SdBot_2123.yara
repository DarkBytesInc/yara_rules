rule Win_Trojan_SdBot_2123
{
strings:
	$a0 = { 9a6a79f0f8b41e53f6e11e44b4fcb482a5de7f0b40291247cb0c1a1edbae8c09a6d395be5b9f94effca9b6c3716969174723c3cd69472fca83b81f76e58af3ed52d2d057af0aa745ba7708d20511b1a4d4c41d8d3209934b7e20cc1fc827fc3e7ec6 }

condition:
	$a0
}

        
