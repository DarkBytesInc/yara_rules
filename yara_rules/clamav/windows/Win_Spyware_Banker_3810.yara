rule Win_Spyware_Banker_3810
{
strings:
	$a0 = { 28401420c54145191f45620508044e7bc90841ddaa976e7731bb9dee74fe1dfe12f7b99dc816f77205cbdd80dbb902bf8e41bab05ed6f20ad602bae405ae416eb920dae41af5c9056e4035dc905a6406db901ebb906eddc81777701bb9705bbddcae6e777ffffff6fbfef9f3efde73cf3ef9e7df3cf39cfeff3f7f03327022898c168b459ec761de8905f43f }

condition:
	$a0
}

        