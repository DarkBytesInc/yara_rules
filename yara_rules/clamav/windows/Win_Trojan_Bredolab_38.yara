rule Win_Trojan_Bredolab_38
{
strings:
	$a0 = { 8d05688a680089188d05f0896800505b8933578f05fc896800528f058b8b680081de4372000051 }

condition:
	$a0
}

        
