rule Email_Phishing_Bank_1524
{
strings:
	$a0 = { 504159464c4f57204741544557415920414c455254 }

condition:
	$a0
}

        
