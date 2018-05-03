rule Email_Phishing_Anglo_1
{
strings:
	$a0 = { 596f7520686176652031206e6577207365637572697479206d657373616765 }

condition:
	$a0
}

        
