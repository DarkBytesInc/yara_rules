rule Win_Trojan_Mybot_8462
{
strings:
	$a0 = { c084bd955040d5df88d9a66812759beb766697be40a97ce7d9d2524d01fae13ae976dbe85e4c69d9495da529543bc95f079fab7f9adb1912e87227fe7a5fa1e4f8205d4250764dc9f09050e044ceeacf7edd5f102a }

condition:
	$a0
}

        
