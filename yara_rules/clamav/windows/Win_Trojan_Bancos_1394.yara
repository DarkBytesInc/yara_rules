rule Win_Trojan_Bancos_1394
{
strings:
	$a0 = { ee4bcb320bb8bf689bb4a6fde69a0354c16c5f1ac6e71c6e8123d925e183787592e6038744dabe9dbe9be84f927acecc1913ecf0cb1fd497adf6051a58d8404621e928ec4fd8a0084626ff2eb4ae1c2dbffa17dbaf224528a43538cd99c9871dcf566cd22882e45d }

condition:
	$a0
}

        
