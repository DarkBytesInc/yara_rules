rule Win_Trojan_W_214
{
strings:
	$a0 = { 6f76696540f8bff0004d69630b736f667420457863656c1a67f8b96e0101bc6f00946d7700b0cf2e3f0b401d10b0171c }

condition:
	$a0
}

        
