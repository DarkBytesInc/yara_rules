rule Email_Phishing_DblDom_31
{
strings:
	$a0 = { 2f7777772e706f7374652e69742f7777772e706f7374652e69742f }

condition:
	$a0
}

        
