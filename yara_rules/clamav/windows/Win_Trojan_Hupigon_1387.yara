rule Win_Trojan_Hupigon_1387
{
strings:
	$a0 = { 964238ead9d1f28a70e9d93ca24db4bfdaaef749bdeacf13a1a27bc7144ac203af7acf5e9f7585dfa10c78c964c32ff57efae8ff0a55f3a0d31139730284b1d9b501e5b0203021ddacb0de9de9e12dcea3db4c668c7efa34a748942f730ad72ee74dbf3fcb0b0b77d8e6995a79b41523261fd08bfadc }

condition:
	$a0
}

        
