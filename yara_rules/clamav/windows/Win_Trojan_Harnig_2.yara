rule Win_Trojan_Harnig_2
{
strings:
	$a0 = { 6e0000005c646c2e6578650052656769737465725365727669636550726f6365737300006b65726e656c33322e646c6c0000516870104000ff1518104000685410400050ff15141040008d4c24006a0051ffd048f7d81ac0fec059c3687c1040006a006a00ff }

condition:
	$a0
}

        