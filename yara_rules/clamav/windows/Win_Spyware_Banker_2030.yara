rule Win_Spyware_Banker_2030
{
strings:
	$a0 = { a7f49303b2ce9f43eb92038c3d8c4fb8f498bb7945639a4b4933826da1602820a5bf47c97cbfb57299819e71733e440d25609880dd4dedd5d3d353e2b98ab597092de614df1c4900690cf42526cb02d325ea14dc36023861dea36d337e69f58bd2da089fc69046abb21940c78586c9729d17d0dfd21478bc7b77ed9c1cc9bd7e }

condition:
	$a0
}

        