rule Win_Trojan_Spambot_110
{
strings:
	$a0 = { 5365f93a37ed29cd4562e362ffffffffe82bde7d197a7f3aea8c247e1d742c34e9723e5d3589433b00ac1538a5d4b6b226fe0ff070bf619f3fe5b2e43aa1d5b93883ffffc1df8944b143f1753bd9fe6c58fa7b67aa62e5829d48ffffffff503461f02431fc2e886916ae21ef7ea8 }

condition:
	$a0
}

        
