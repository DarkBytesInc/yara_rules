rule Win_Trojan_Beer_7
{
strings:
	$a0 = { 1e06505351525657559ce8b5ffe933050000000000000000fae8a6ff2ec606dd01001e06505351525657559c0e1fb8 }

condition:
	$a0
}

        
