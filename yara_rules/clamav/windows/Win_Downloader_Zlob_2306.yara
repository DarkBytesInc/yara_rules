rule Win_Downloader_Zlob_2306
{
strings:
	$a0 = { a5488d9c36cdb44c45a53ec771027d3b7f2cade0cbd2ff4ff15966c3fbff48701f9cfcf253525b5248d203bee6a29b2233d2943576d8ef1d177dc6633229772c90e80727f1cb2f5642eeae228288 }

condition:
	$a0
}

        
