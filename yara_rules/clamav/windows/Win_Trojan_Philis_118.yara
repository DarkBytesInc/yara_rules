rule Win_Trojan_Philis_118
{
strings:
	$a0 = { 404860c1cf81c1c781e800000000c1cecac1c6ca560f02f75e5ab8050100005633f75e03c256f7d65e5053568bde33f75e5bba0000000064ff327403 }

condition:
	$a0
}

        
