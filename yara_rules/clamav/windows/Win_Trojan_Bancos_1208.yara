rule Win_Trojan_Bancos_1208
{
strings:
	$a0 = { 50aa5939fb3a6e39c8af50aeaa17d0fe0c3f9a34fe55b466321993e0b29c93f5aa549c047e96bb800e42a079ad5a1f8a97e3cec9bd602e040c19a074f74e29bdfcfd7e0eebf73e6f2bddbc8505081f570a7acb99d24907b6229890013fa15f }

condition:
	$a0
}

        
