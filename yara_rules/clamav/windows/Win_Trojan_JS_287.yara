rule Win_Trojan_JS_287
{
strings:
	$a0 = { 7273696f6e5c5c72756e5c5c222b6e616d652c7374617274636d64293b7368656c6c2e72756e2873 }

condition:
	$a0
}

        
