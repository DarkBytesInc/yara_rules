rule Win_Worm_Drefir_18
{
strings:
	$a0 = { 6c74616765205669727573205772697474656e2042792044522d454620286329203230303500000000000000000000000000000000008d852b1d400050 }

condition:
	$a0
}

        