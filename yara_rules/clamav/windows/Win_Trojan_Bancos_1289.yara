rule Win_Trojan_Bancos_1289
{
strings:
	$a0 = { e3a00dedfce2b6c736cd03d541099ad0df2ed06a373103c5b27396b813cf5c6186c465065b18b65a605ca75063ecdae8d4408d36a83b3b3211f203190c54ba993ad2a2b078301c5207df66be3b433f0eca1cddddc3fe2ef6e7ef }

condition:
	$a0
}

        
