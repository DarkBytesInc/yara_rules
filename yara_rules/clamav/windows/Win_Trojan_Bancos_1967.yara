rule Win_Trojan_Bancos_1967
{
strings:
	$a0 = { 834753a4832358114ab9610c8afa31cabd863a62d8a75d6426ca907b3a405a1302d66618985464a422d8cc6245c0bb848dc66d7704c45e92e8b7b277127726ad7e637f2702d4f065e166cb786c7de8ce212837c63bcb1bda10 }

condition:
	$a0
}

        