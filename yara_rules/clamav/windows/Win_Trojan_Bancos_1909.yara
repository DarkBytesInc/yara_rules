rule Win_Trojan_Bancos_1909
{
strings:
	$a0 = { 0b166daff770cec508143469d24c070115a4dbbbb073fec60ba94244bc4d18b2a2418e885268939e4f2e2ec935bd9c494997f010a944ec1841d79479fe292fdaeac8902abcb794f4de9aa6bcebfe887cc64514aa8ef49475b6d9 }

condition:
	$a0
}

        
