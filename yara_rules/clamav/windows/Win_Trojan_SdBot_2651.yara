rule Win_Trojan_SdBot_2651
{
strings:
	$a0 = { dea97ae8798e985f8514bf333dd5d05479e81389887d7245967fafd5ba570cd6684ea351f803e5f9de1591915ffd5539651a4a931ef2ce7a0444b6b970849318e3618abf786862ba477b8ee5e6a608d305f4db66055dc4e71e64c1543d7810cfcfcd09e3632f1e11437bb1b51ba26f7934e08123030de33a990e2050d6f707631d41948721fbe52a }

condition:
	$a0
}

        