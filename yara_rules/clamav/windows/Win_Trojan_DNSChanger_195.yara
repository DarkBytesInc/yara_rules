rule Win_Trojan_DNSChanger_195
{
strings:
	$a0 = { 4f34b9fc3eb1fcb9043a4fdf08fa64f98a3b64f9b17e1e366cb70ebafbdc3eb7bc4e237a3a6ac54e1e2ad2cfc6c5c563befa634f13c54e1e36d22ec5c5c5befa634e21b7bc9e217a3a6ac54e1e2ad2a8c5c5c563befa634e3f503b6264f9b9f2c564f96f }

condition:
	$a0
}

        
