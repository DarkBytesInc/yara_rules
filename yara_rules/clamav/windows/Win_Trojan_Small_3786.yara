rule Win_Trojan_Small_3786
{
strings:
	$a0 = { 7fe4a2382a0c87fd268fc22dc1ca37f9c11e8ffc014820217a59ec4d2a0c04607366056175525962e9598fd57b5d576f7d877931a9690c39a14b383aed03b3712c89cdb067f07a06a7bc0c382a0c }

condition:
	$a0
}

        