rule Win_Spyware_Ardamax_13
{
strings:
	$a0 = { 8b461c50ff1528664300a14c82440083c40485c0743ea15482440083e8007411487407b860ea0000eb0c }

condition:
	$a0
}

        
