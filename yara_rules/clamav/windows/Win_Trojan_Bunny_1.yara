rule Win_Trojan_Bunny_1
{
strings:
	$a0 = { e4009a0d0082005589e5b800019acd02e40081ec00019acc018200bf00000e57b8200050bf52001e579a720073 }

condition:
	$a0
}

        
