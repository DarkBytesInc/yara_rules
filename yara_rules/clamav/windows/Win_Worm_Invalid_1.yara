rule Win_Worm_Invalid_1
{
strings:
	$a0 = { 616c69642e576f726d006841294000e8f30100006a086a016a00e80d000000496e76616c69642e576f726d006841294000e8d101000083f8000f8498feffff68452940006a016801680000ff3541294000e8ab01000083f8000f8478feffff6a0068800000006a046a006a0368 }

condition:
	$a0
}

        