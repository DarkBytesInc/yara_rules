rule Win_Adware_Favadd_7
{
strings:
	$a0 = { 6d6d2e69636f00fe10195cbcbac0ceb5f0c4ab20b0b6b7afb8ae20c4bfb9c2b4cfc6bc2e6c6e6b00687474703a2f2f7777772e626f622e636f2e6b722f436f64652e7068703f7376723d6c426f52 }

condition:
	$a0
}

        
