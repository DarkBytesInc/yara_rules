rule Win_Trojan_AOS_2
{
strings:
	$a0 = { fab8455992cd169292929292929292929292b97e01bb2d012e812f000083c3024975f51e0687ca87ca87ca87 }

condition:
	$a0
}

        
