rule Osx_Trojan_Imuler_1
{
strings:
	$a0 = { 2f55736572732f6170706c652f446f63756d656e74732f46696c654167656e742f }

condition:
	$a0
}

        
