rule Win_Worm_Kolab_15
{
strings:
	$a0 = { 68c4164000e8f0ffffff0000000000003000000040000000000000008e24f7904af4524ba807768d31fc6ed90000000000000100000079746529204166495275445046534a57556900696d200000000007000000d01c400007000000881c400001000000 }

condition:
	$a0
}

        