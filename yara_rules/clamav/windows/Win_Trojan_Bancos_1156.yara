rule Win_Trojan_Bancos_1156
{
strings:
	$a0 = { db3a7d5f958147ab453dbe09c0560dd122aefefa0e7dffd53ee7c10e9dbecf83f01cdbd944c18cb0fa0d7dff95e2eeaf0ea5fdd7a2bc863894f6dadafbaf3d98832d28edd2befffabff66087b6a0b4effbfe6b0fc4 }

condition:
	$a0
}

        
