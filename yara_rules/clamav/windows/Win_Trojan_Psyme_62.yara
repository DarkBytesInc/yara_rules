rule Win_Trojan_Psyme_62
{
strings:
	$a0 = { 6f6e6572726f72726573756d656e657874776d313d226f222622626a22262265637422776d323d22636c6173736964227a776d3d22632226223522262235222622362226222d222622363522262261332226222d2279776d3d22636c2226227369222622642226223a222622626422262239362278776d3d222d222622392226223822262233222622612277776d3d222d2226223030 }

condition:
	$a0
}

        