rule Html_Trojan_DelfAR_1
{
strings:
	$a0 = { 5053ac0c572214ab606db0036d181c041f8bd92e43097e9af8db0f84af008ce38d43014ec0cc96e4ec1e90b7df1e03b9ec6311807c1affde06d6f05c7430bffe643230d98bfa0272f6a4b5cb4f36cbc33cb4843e5617fcc9802c145550e946cf }

condition:
	$a0
}

        
