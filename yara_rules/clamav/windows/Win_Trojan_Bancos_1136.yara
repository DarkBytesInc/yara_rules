rule Win_Trojan_Bancos_1136
{
strings:
	$a0 = { 3e1c79aa6c7ea893d0d56f39ab6de6f6cfca20e40599114f13ccae725b62d5cb220cb37f523f388680836c8de27d55d714cfd31bdbae28f2366c104770f1eff88cd702b7b6f7ab2a7658bdd204192779f685e86019ca2cdaf7f8c9d5b52a07ed9ee6 }

condition:
	$a0
}

        
