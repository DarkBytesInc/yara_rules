rule Win_Trojan_Twno_9
{
strings:
	$a0 = { 672b80790c00b5a4d1a44facfaa5f7bdbaaaf9c251a460b82e002e002e0012690574696c6524126c0100641a1d64690261610c67b780056c000006641d690261610f6c00001e646e04236901690c6c01002469026161646e081d67b88005690169126c0000060c7908004100750074006f004f00700065006e001e64 }

condition:
	$a0
}

        