rule Win_Trojan_IRCBot_677
{
strings:
	$a0 = { cc2c883e01f4dcdf4c2dd876793cddc8b4e68929f93d8d92cc2c883e01f0dcdf4c2dd87a793cddc8b4e28929f93d8d8ecc2c883e01ecdcdf4c2dd84e793cddc8b4fe8929f93d8dbacc2c883e01e8dcdf4c2dd852793cddc8b4fa8929f93d8db6cc2c883e }

condition:
	$a0
}

        
