rule Win_Trojan_Dialer_93
{
strings:
	$a0 = { 41c00f70b084c3847615915a04f2bb0edea74e544558555308090689c420c4d1a81edb014ef12ea716ac9b5af7729b0d1185d7a278632f8a67d06e6f5b9653b9 }

condition:
	$a0
}

        
