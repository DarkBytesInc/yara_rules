rule Win_Spyware_Ardamax_20
{
strings:
	$a0 = { 4c6f6767696e67456e61626c6564000053746f70204c6f6767696e67000000005374617274204c6f6767696e67000000417264616d6178204b65796c6f67676572 }

condition:
	$a0
}

        