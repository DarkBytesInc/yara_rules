rule Win_Worm_Haptime_2
{
strings:
	$a0 = { 67736626225c696e73746c6f672e68746d22 }
	$a1 = { 67736626225c696e73746c6f672e68746d22 }

condition:
	$a0 and $a1
}

        
