rule Email_Phishing_TSBBank_1
{
strings:
	$a0 = { 446561722056616c75656420436c69656e74 }
	$a1 = { 73686f756c64207570646174652872652d636f6e6669726d29 }

condition:
	$a0 and $a1
}

        
