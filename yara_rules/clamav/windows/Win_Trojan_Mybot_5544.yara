rule Win_Trojan_Mybot_5544
{
strings:
	$a0 = { f08a724ad3c25ca2723635931924fbaa363c110c8f722a627094ecf2a13cade7260857ed399bc9d7b9ee377474b5d1b8fe516bd696ba53c11208952bc76b5907d24dc2912b30 }

condition:
	$a0
}

        
