rule Win_Trojan_Hupigon_556
{
strings:
	$a0 = { bb7a03fea04e5b6588fc3175a7c940be86d4823dc3a68927c59de92a3828fafebfa48f3cc75f2bd01c605e7166d40e9ff42baeb1ca0baafe8abc9b379d32b87b80bb0ce2ac142071e9ec596ae8d4ad7e898bc894d7aaf1414fec0850d3c8f27125eb01f93eb26fafc6 }

condition:
	$a0
}

        
