rule Win_Trojan_CHRootkit_2
{
strings:
	$a0 = { 6a6176617363726970743a616c6572742822d5e2b2bbcac773656c656374c3fcc1ee5c6ec7ebb4f2bfaacafdbeddbfe2bfb4d4cbd0d0bde1b9fb5c6ebaa3d1f4b6a5b6cbcdf86c63785c6ed5e2b8f6c4e3bfc9d2d4b5b1d7f6d2bbb8f6616363657373b0e673716cbaf3c3c53a2d292229 }

condition:
	$a0
}

        
