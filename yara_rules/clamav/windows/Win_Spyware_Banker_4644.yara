rule Win_Spyware_Banker_4644
{
strings:
	$a0 = { fbf314558c531c5e9b9fa928e38a6a1ed764bd818a1b2fedc7f0572dadbc7bd1cf4f0ff569d73e6444770e49d51a3cbb17d37d7306516994d47ba2e6684b22f364a724bb306d6e42571b4eabcecaeef08760b7cf2a300eff26df32eafbaea32356a664c73aba522ae6a112882ba5d13f4a7221defc73 }

condition:
	$a0
}

        
