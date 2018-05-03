rule Email_Phishing_DblDom_70
{
strings:
	$a0 = { 687474703a2f2f307833422e307835442e307833382e307846392f7777772e7061 }

condition:
	$a0
}

        
