rule Win_Trojan_Bancos_710
{
strings:
	$a0 = { b106d66904d58be13bc075779f78e99b9f4f921963a480a488f5e3e4eb1eba2261134932f11d279d9371d941a816dd87186e8de874ef2901061d7419eba1f4c3df }

condition:
	$a0
}

        
