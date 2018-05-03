rule Email_Phishing_Pay_270
{
strings:
	$a0 = { 322e38333a393939392f776562736372722f696e64 }

condition:
	$a0
}

        
