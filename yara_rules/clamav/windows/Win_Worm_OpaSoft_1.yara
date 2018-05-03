rule Win_Worm_OpaSoft_1
{
strings:
	$a0 = { 56e0ad4aa8dad9d587ea37a98e049c45eb7de06d1209d128563402782077fbffffc138164602d5851001bc5935ba79fe46c0ed2c48e8aee64797ffffff4b8059 }

condition:
	$a0
}

        
