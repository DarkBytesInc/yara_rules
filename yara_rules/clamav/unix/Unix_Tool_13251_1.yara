rule Unix_Tool_13251_1
{
strings:
	$a0 = { eb0e5e31c9b11cfe040ee2fbfe0656c3e8edffffffea0d5d30bf8745064f5355af3a4fcc7fe7ecfefefe2e61686d2e7267 }

condition:
	$a0
}

        
