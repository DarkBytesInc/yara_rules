rule Win_Spyware_Banker_3324
{
strings:
	$a0 = { 54332d15e47b23b969e581e4a0a0f2fee8fcb38ece3ed58bc29dc8e043f077637c47bb1ba934a0467a88bc7a324f62db1bc2d8b419ee3f6e8a9c0ebc03294e99a150c19dfd5850b9f6208f468fbd2c4a3c2db2bc74 }

condition:
	$a0
}

        
