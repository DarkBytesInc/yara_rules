rule Win_Trojan_Qooloc_13
{
strings:
	$a0 = { a695b9fb7faad6a9b3baa711e459d7be0cadb0aff8bc758d99bf7a225af4cb79daa86e7c0fed12324c6597f6089ff116dab09514ef700e731f8270f0cb8b57c97e5e97f7baf90e6a7ccbea7285e4be8a73a1fcebe3b8c1e14a0df13f0add6dd0f1cd83b88c2cd3def9d85e4cd05cb071613ed289e0cf28aff9b4fb }

condition:
	$a0
}

        
