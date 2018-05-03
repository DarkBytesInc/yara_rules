rule Win_Worm_Stration_605
{
strings:
	$a0 = { 503a73bbece224cff3353529d276d9c8fe1ba2fbec61696f64b563f44c304071f1153c4bfe21c84a3ad16ff71da05ab9a5ba2171b845c07351c7b3f60da05aba }

condition:
	$a0
}

        
