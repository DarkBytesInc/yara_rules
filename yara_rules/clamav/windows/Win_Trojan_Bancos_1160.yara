rule Win_Trojan_Bancos_1160
{
strings:
	$a0 = { e0682273524106ff98c42258fbb543eae3414c2c59461ecf477cd7d3af4e62850537c99c779bafa2ab68f7f9e10e4afdcaa4feadad65d77a5715d5a5553a6dd1450a5332805fd7cfe4b50288e1194fc83cdb10e93acadc5c1079cb774c48fe }

condition:
	$a0
}

        
