rule Win_Spyware_Banker_3981
{
strings:
	$a0 = { 08551a0d591f1ab390422913776474d0b99cf35cefc1bdf8d7f417f2816dec896f5ed837ab217aaec16ac0795d905484a36f6c16b802db9215ae48af39b07e99a0f173744ae405ae6c8dbd915eeec90bd9d856e7765efa7fffff2f7af5ebdfaf9f3cf7e7bf3dfbf9e6679faf9ebefe9033405b9b4201e87b9e47cea3f948f108f98478547c9a3c1a3c0a33c8 }

condition:
	$a0
}

        