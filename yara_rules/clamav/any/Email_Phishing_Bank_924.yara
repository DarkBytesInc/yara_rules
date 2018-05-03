rule Email_Phishing_Bank_924
{
strings:
	$a0 = { 772e6f6e6c696e6573657276696365732e62697a2e74632f6c6f67696e2e6874 }

condition:
	$a0
}

        
