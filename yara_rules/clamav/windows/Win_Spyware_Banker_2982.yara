rule Win_Spyware_Banker_2982
{
strings:
	$a0 = { acbb935c35f7000de32de1f6b6d3f49b3cc7ad7b5d9bda92e32fb875aaf73a70597d2cf7971b8ae07bab6ccd96dfef6c1936d86f0d4c3cfa06aa1b2ec02e001338ac48cf570cd4a72e10940d839033bb195591bb5a04f893f74014d0d5ce88faf17c2470 }

condition:
	$a0
}

        
