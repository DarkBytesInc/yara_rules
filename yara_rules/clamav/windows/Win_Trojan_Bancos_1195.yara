rule Win_Trojan_Bancos_1195
{
strings:
	$a0 = { 452be6989d5cea7baeca2a15747cb9bcaa0d13fc92294c0de6a332d454e855e295eeaaf16fd5a95764cf461134f9ab43fa224b19463ad477c0c5ae258ba67a3557ecfb8f58f82cd929ce0f6aab5008d300c5f71fade5fdbe5310d5e5daa9cee468b00c66ed86da91b18ac1a485c1d5d9babb428de65798706db9d9bff2f1e8ab }

condition:
	$a0
}

        
