rule Email_Phishing_Azon_16
{
strings:
	$a0 = { 74652e6564752f7e676172636961742f616d617a6f6e2f696e6465 }

condition:
	$a0
}

        
