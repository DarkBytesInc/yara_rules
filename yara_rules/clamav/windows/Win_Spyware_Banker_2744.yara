rule Win_Spyware_Banker_2744
{
strings:
	$a0 = { fa9f042bc0fb8db1081e13a1d2d2f66d06bcf1c302060dd207d989f2907cb78f603ff43a034842fc84bb9e2b4635ac0853bf8c06bc33b676357e5e2bf602496e660592079d2b0ca288cfc2be46a7 }

condition:
	$a0
}

        
