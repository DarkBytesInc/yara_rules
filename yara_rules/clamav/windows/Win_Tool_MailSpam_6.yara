rule Win_Tool_MailSpam_6
{
strings:
	$a0 = { e9ff49f9ffebeb5b8be55dc3ffffffff08000000445f4d4276302e3100000000ffffffff12000000445f4d61696c426f }

condition:
	$a0
}

        
