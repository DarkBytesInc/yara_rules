rule Win_Trojan_FU_1
{
strings:
	$a0 = { f5009a4901bf009a0d005d005589e5b800019a3005f50081ec00019ac40ff50031c0a36800bf52001e579a0000 }

condition:
	$a0
}

        
