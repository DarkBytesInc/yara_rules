rule Win_Trojan_INet20_1
{
strings:
	$a0 = { 0880fb7a770380eb208a7fff80ff61720880ff7a770380ef2038fb74d80fb6c30fb6d729d05b5f5ec39053568bf28bd88bc6e80bdaffff508bc6e8c7dbffff508bc3e8fbd9ffff508bc3e8b7dbffff506a016800040000e8d2f2ffff83e8025e5bc3535657558bea8bf88bc7e8d1 }

condition:
	$a0
}

        
