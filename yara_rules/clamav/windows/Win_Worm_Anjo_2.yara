rule Win_Worm_Anjo_2
{
strings:
	$a0 = { 2f6463632073656e6420246e69636b20633a5c667265657069632e7a6970 }

condition:
	$a0
}

        
