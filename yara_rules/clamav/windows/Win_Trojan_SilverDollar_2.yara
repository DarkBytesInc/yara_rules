rule Win_Trojan_SilverDollar_2
{
strings:
	$a0 = { 8bec5633f6b8030550e8eb0159e8a7000bc0740ae8680046fe062806eb08bab008b43bcd21463b3625067ce1803e280600740ab80f0550e85e0159eb3a803e }

condition:
	$a0
}

        
