rule Win_Trojan_Popwin_7
{
strings:
	$a0 = { 529d12cf0acb571fc0ad78f90a5d9e02e4fb1e234e0b989c7f39291aca5351bb7b2cf164bf77cbaaeb3b1d05d51cb99bcff1b8bff9e6a4f3b5f0016e946f95d17db74bdaa7be5e7be161334aeb3a3f71317c392c32d8223c3b72dd6a142f8fc45d56fef4eec0fc1b9552e36c3295a148 }

condition:
	$a0
}

        
