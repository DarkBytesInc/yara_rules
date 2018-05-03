rule Email_Phishing_urgent_1
{
strings:
	$a0 = { 4465617220437573746f6d6572 }
	$a1 = { 73656c65637420612074657374207175657374696f6e }
	$a2 = { 2a416e737765723a }

condition:
	$a0 and $a1 and $a2
}

        
