rule Win_Trojan_Bancos_1380
{
strings:
	$a0 = { 68f01ea1f173feed773422f87a6c08dfe416212787ef35b49ee437bc84f2128b89608ca13cf4f51e10904f92c18bdaec787a1f8296db8d59e2317fb87c5d56aed848d6bf2b567cc8a94485d76bd810467fb4badd1a3c53cef38cefbf3d0c8384a6e8ed2ab3ab1451 }

condition:
	$a0
}

        
