rule Win_Trojan_Agent_33693
{
strings:
	$a0 = { a4034993a833cf9878b0046adc6cbc05ba8bad8fd07d4a30558ccd22ea7d7464a910327d24b8ebff47df0de97b7ca2c1a07618ab8065c1392f1d936e9a6fbf476ded46ad128ed15033f7edf7395dcbe86d826caab8a857c48fde0123f3da8e }

condition:
	$a0
}

        
