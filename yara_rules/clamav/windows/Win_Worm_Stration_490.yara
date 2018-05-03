rule Win_Worm_Stration_490
{
strings:
	$a0 = { 9165690b3feb79a0bd81a9549b1b7cd06ef429a078b1fb5db3e27e111e2ae0619adb065657f8279bcdf57c6a2b9c2b6441446ae9807ffb2b37f78545b9fa22376c4c7e }

condition:
	$a0
}

        
