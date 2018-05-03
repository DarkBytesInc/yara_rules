rule Email_Phishing_Kiwi_2
{
strings:
	$a0 = { 687474703a2f2f746f706f667468656c696e65636172776173682e636f6d[0-8]2f6b69776962616e6b2e636f2e6e7a2f }

condition:
	$a0
}

        
