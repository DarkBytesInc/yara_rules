rule Win_Trojan_Hupigon_305
{
strings:
	$a0 = { 62a147ea7c0980ef593834584737e5c165147c2a10a501db44dad75c51a3b36be3516904dcb26a4bcb2f9ddb1e7eead167e019ecb37d373ff305cb2304397a53d178ecb615ccba8ae4562333ad8e19aac4ee6e594febe0071288 }

condition:
	$a0
}

        
