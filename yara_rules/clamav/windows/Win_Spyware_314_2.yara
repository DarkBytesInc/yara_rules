rule Win_Spyware_314_2
{
strings:
	$a0 = { 80aac72aa4ba6eae059ec7d57c3572a9218a28d737714b7003f0b47e884e74fadfa7d2a8b67e62a9a3c8fdaf466ebe904be2f9a8c274fc328008cccefe20d01330303a11d81e6c1b2f8a5e3f02f4d8092c10b5bde8b023e2637d757b4caee0 }

condition:
	$a0
}

        
