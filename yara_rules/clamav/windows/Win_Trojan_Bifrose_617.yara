rule Win_Trojan_Bifrose_617
{
strings:
	$a0 = { ffa676a9abff8a360820009ca26c3b88abff8a5e082000c164ffaf2fade46108003501a9357e2c95a26c28abff8a3a082000c6a27aa928c6a266358228abff6bc6a27aa928c6a25e350828abff6bc6a25e350828c6a26635822874597fffffc16208e3a27846bc2000c6a2664504c5aa7844a6ff1d05ba8e1de53a8a45248044a6ff1d2580ba07c1a2780120201de5baed9960f5828d }

condition:
	$a0
}

        