rule Win_Adware_Drivecleaner_1
{
strings:
	$a0 = { 6e633125302306092a864886f70d010901161672746f6e65406472697665636c65616e }

condition:
	$a0
}

        
