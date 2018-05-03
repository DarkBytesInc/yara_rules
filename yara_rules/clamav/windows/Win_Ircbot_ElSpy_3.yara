rule Win_Ircbot_ElSpy_3
{
strings:
	$a0 = { 4c31355f424d502e455845202f590d0a64656c20636f7079782e6261740d0a6374747920636f6e }

condition:
	$a0
}

        
