rule Win_Trojan_Agent_33363
{
strings:
	$a0 = { 84bb43eff1ca40846449e2a874a2460c981378c9c091f864e0cb5f51edd950f787cce2e9f93210fcaf6e5b0383522dfe70c134e4baf7d5261788de6634f33dbc4ff9710def8a1991a1760c8eb678e33faeeacc416060ee9c5b94bd1e0dc1 }

condition:
	$a0
}

        
