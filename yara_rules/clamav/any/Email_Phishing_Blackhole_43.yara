rule Email_Phishing_Blackhole_43
{
strings:
	$a0 = { 3c68313e706c656173652077616974[0-15]2e2e[0-15]6c6f6164696e67[0-15]2e2e[0-15]3c2f68313e3c62723e }

condition:
	$a0
}

        
