rule Win_Trojan_Kuzin_1
{
strings:
	$a0 = { 73636f77e15287f0b6736961a64968796f7513042073747c77735f604480786a529000fd0af8 }

condition:
	$a0
}

        
