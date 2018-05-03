rule Email_Phishing_Pay_156
{
strings:
	$a0 = { 446561722050617950616c20 }
	$a1 = { 636f6e6669726d20796f7572206964656e74697479 }

condition:
	$a0 and $a1
}

        
