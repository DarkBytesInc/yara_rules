rule Win_Trojan_Fraudload_8
{
strings:
	$a0 = { f2d359cdfbffffe9b1bdf4400a05feffffb95e49806c8d32fdffc4fff48ac55a3e7053e380c5c492fdff82cffdff2985b9fdc47ad11fc490fdffc4aafd3cc4ff1be4e0be550b0539986145e91f2e27ee00aec468c57348f9f0888152fdffc4f031fdc4f6 }

condition:
	$a0
}

        
