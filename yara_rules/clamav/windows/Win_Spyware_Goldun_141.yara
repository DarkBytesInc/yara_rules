rule Win_Spyware_Goldun_141
{
strings:
	$a0 = { 08e9f144342a1f297d4175267ebb1c155f8575fa81eefe0e7cfa5363e506811c084567f9bbd86201321c67f1c217f75b33f6e1de81e6037e0d1c784e1af300de0aee8d4f01d921991c7e50 }

condition:
	$a0
}

        
