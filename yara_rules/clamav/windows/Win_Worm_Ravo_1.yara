rule Win_Worm_Ravo_1
{
strings:
	$a0 = { 6e313d2f6463632073656e6420246e69636b204348414e4e454c2d52554c45532e7a6970 }

condition:
	$a0
}

        
