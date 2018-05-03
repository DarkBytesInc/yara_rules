rule Win_Worm_Calgary_1
{
strings:
	$a0 = { e800000000eb249090908db538104000b9ad3c0000eb1990909081ed0510400083fd00741390909090ebdf5f8befebea }

condition:
	$a0
}

        
