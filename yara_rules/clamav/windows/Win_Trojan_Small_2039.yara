rule Win_Trojan_Small_2039
{
strings:
	$a0 = { 6801000080689289400068819740006871974000689f424000ffd0 }

condition:
	$a0
}

        
