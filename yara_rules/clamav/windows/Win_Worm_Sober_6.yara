rule Win_Worm_Sober_6
{
strings:
	$a0 = { a4091b337027a37972906f2f015439644f00d29c3c0c447815063939c818c8511c8009c056f68f2f031588ff9b4e61006200630064006500664bd4b4142cc169c56bc76dfec2df2e05006fdd00710072 }

condition:
	$a0
}

        