rule Win_Trojan_Agent_34929
{
strings:
	$a0 = { 4ebad3a55bb6cbd01095def551e15ab04a9dc4d0768ee0be5283a1931b80371b4b11e8b707a796b15190e0a05c95a3e0176b3cd8eed7f3a77a8859f2eeed5a2686ef82947fa18f935987559f3ded5c12578c91a422a2ffb13ed0 }

condition:
	$a0
}

        
