rule Win_Adware_Adsplus_1
{
strings:
	$a0 = { 427579204e6f772121210000612b0000433a5c0025733f464e3d2564265549443d2564265356433d256426434269643d2575264c617374506c757341643d256400000000687474703a2f2f7777772e646f75626c65636c69636b2e6e65742f6e657741 }

condition:
	$a0
}

        