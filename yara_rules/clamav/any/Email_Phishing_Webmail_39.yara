rule Email_Phishing_Webmail_39
{
strings:
	$a0 = { 53656c6273747665727374e46e646c696368206bf66e6e656e20536965206175662057756e7363682077656974657268696e2049687265205041434b53544154494f4e206e75747a656e2e204869657266fc7220697374206c656469676c6963682065696e204c6f67696e20756e746572 }

condition:
	$a0
}

        