rule Win_Trojan_Bancos_1947
{
strings:
	$a0 = { d2d272abd2bed4914a60b8dcc3b344f002d6362852a070336f728ddcfbd881987aa570e9beec61aafbf5c493125a6d567a7bbfcfec15c908cd851cf51800d1a34cd790f16c24dd64b8c9a72760c8f85d9efe5b636d76275a4a7b }

condition:
	$a0
}

        
