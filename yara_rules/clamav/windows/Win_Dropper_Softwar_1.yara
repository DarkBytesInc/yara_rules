rule Win_Dropper_Softwar_1
{
strings:
	$a0 = { 5ce90eb4c2d5fae48038ccb38c57e90eb4dfcafad104d4f78c558470fbcf04fcaf8c7d04c497dcbc54228c4dd9d808711823854ffa880fb000fb846488b788fa8cc864623f8ed0d1854ffb8ccc6d551cd404fcab8c7dcf5e6f8c7f803881a4c49f04fc938c7d1e4e6f8d8c7f04898c4d }

condition:
	$a0
}

        
