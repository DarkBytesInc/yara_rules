rule Win_Trojan_Hupigon_316
{
strings:
	$a0 = { 9721aa75bcb58eb257bca5196cdcf254d2c9891fe3ed75954179f47eeeb40f114d98c0d4d0ee0310df5f00e88e34220c1b8391b57c88c97ebfa854878b74d4d9f8319e873466da34df57ae81ede10e8c5e7928c4516a5afb2001 }

condition:
	$a0
}

        
