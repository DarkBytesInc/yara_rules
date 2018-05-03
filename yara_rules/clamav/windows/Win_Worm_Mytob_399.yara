rule Win_Worm_Mytob_399
{
strings:
	$a0 = { be88014000ad8bf895ad91f3a5adb51cf3abad509751588d54855cff1672572c037302b000 }

condition:
	$a0
}

        
