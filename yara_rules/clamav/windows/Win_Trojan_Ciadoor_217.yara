rule Win_Trojan_Ciadoor_217
{
strings:
	$a0 = { 55f25e70ee7692a3aeeef6e5f4efef5ef6e7f4efef1355f25e70ee76ef9f8feef60ff4efef13c67682a3aeee76b2a3aeeef67cf4efef5ef67ef4efef11553e76a2a3aeee7652a3aeeef644f4efef5ef646f4efef11553a765aa3aeee76b2a3aeeef6acf4 }

condition:
	$a0
}

        
