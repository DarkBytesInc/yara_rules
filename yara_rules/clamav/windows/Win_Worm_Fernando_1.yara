rule Win_Worm_Fernando_1
{
strings:
	$a0 = { a4803e0075fa5ea46a01681c1040006805104000e814000000ebc7 }

condition:
	$a0
}

        
