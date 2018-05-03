rule Win_Worm_Stration_436
{
strings:
	$a0 = { c0826ccbd179909ee57177efdfc4a51bd0220c3193b82c2639fce64505a2f5274a005be21c9c14c4c09e4f16b8387fcbfaa2fb92df06f9e9832382bd630926699134931af5289cbb5189286e728eedec }

condition:
	$a0
}

        
