rule Email_Phishing_Bank_1385
{
strings:
	$a0 = { 69742773207374726f6e676c7920616476697365207468617420796f752073686f756c64[0-2]757064617465206163636f756e742070726f74656374696f6e }

condition:
	$a0
}

        