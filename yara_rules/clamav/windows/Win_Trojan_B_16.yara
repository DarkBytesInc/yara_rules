rule Win_Trojan_B_16
{
strings:
	$a0 = { 2f62696e2f626173680d0a6966205b202224312220213d20696e66656374205d0d0a7468656e0d0a202020206966205b2021202d66202f746d702f7669722d2a205d0d0a202020207468656e0d0a2020202020202020243020696e6665637420260d0a2020202066690d0a202020207461696c202b3235202430203e3e2f746d702f7669722d24240d0a2020202063686d6f6420373737 }

condition:
	$a0
}

        