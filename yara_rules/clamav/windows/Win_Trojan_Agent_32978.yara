rule Win_Trojan_Agent_32978
{
strings:
	$a0 = { 27c0aa379da80b0938daff091a19932d147fa8225937abd0a0f97cc194e940384b3bceb92d8c08b52751639f4594cf3c337bd83ef93f8a19b723ce91c86dfbb953c97eaa2874bf49f4145fc078c6 }

condition:
	$a0
}

        
