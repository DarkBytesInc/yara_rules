rule Win_Spyware_581_2
{
strings:
	$a0 = { df3e07819fcc1be439e8a7c94590b40ed74b76c1f0de5efe9256a07dc56d56743d1fff158c36a02f4ef7ec08afb03bec6f711967954fb55873f3daac2092a5bb810512170468f8076501a25c1e740129f66558d71f9fd17371d552645d30c1036f772def5714dd9a0d10f181f5364de9e10645e49a54a75863669fd70d608442062d5fd6aebba1252b460b47 }

condition:
	$a0
}

        