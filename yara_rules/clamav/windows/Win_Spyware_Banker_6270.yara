rule Win_Spyware_Banker_6270
{
strings:
	$a0 = { 80c6cc3a673ca0bebeb771895765708804f8226ca35cd90cd3ffbbf698ae7e9f5fa8fceb18d67850284360d1d879dca7e008db23ff734f2ae4282713b4dfcc65970c70b0ce28845ddd4ff3bb9bc757759e6dd91fdb339d6aeef41db8ab1ae8 }

condition:
	$a0
}

        
