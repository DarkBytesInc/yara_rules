rule Win_Trojan_Mkdir_2
{
strings:
	$a0 = { 6d6b64697220633a5c6675636b77206d6b64697220633a5c6271206d6b64697220633a5c636675636b }

condition:
	$a0
}

        
