rule Win_Worm_Haptime_3
{
strings:
	$a0 = { 6d706174682c2268656c702e76627322 }
	$a1 = { 67736626225c756e7469746c65642e68746d22 }

condition:
	$a0 and $a1
}

        
