rule Win_Trojan_Bancos_1090
{
strings:
	$a0 = { e987c0ad350888ed955ab4bbfc14f5a72cadf027505324b9dcd535c802f471fa3c375795c290558582d9a3ce3d21a612a0faf40b1d5d1c248fde9945e19b672e25716db3b2a6dc9ac9a841c59dffe8831659 }

condition:
	$a0
}

        
