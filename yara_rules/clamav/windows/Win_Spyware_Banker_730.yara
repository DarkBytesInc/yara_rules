rule Win_Spyware_Banker_730
{
strings:
	$a0 = { 541c0806a8e067c9a0eab8dfec5ea0ee016def719b6288ba31686b168223c84971a56d2cad34ed7fb6b904f94b3be82021453015740d6c0bfd3b1d2f4cf79f51680577269a316ddc0c274dd0644e87e3dce32abb1cbf2cbcf2f95ddc102561a38cf9379dcc06d67c6b09a50267eb9c4cc60399b31b8ce23ea921d1f83739e9d701ce879e6327672e9bbf2f79685d4277f7ca181d4e4f }

condition:
	$a0
}

        