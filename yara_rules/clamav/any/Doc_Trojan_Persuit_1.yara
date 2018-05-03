rule Doc_Trojan_Persuit_1
{
strings:
	$a0 = { 676f696e666563742e5642436f6d706f6e656e74732e496d706f72742022433a5c494533322e646c6c22 }

condition:
	$a0
}

        
