rule Win_Trojan_Mybot_8458
{
strings:
	$a0 = { be3cce7be48fb43cc31601f0cc04cc2ebcc2e822abb8a9d5742df353eab2f80977e92d84da98923a8b1de1d4e650d1848e535dd82cf9b539cae5656f7f58930d2951722c2911808443741dbb2604cc2ba5e98284e8 }

condition:
	$a0
}

        
