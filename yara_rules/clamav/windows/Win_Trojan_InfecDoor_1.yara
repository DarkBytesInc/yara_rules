rule Win_Trojan_InfecDoor_1
{
strings:
	$a0 = { 6520496e666563746f7200000000558bec83c4f8894df88955fc8b45fce8d06ffcff8b45f8e8c86ffcff8b4508e8c06ffcff33c055686dcc430064ff306489208d45f88b55fce80f6cfcff8d45fcba84cc4300e8ee6dfcff8d45f8ba84cc4300e8e16dfcff8d4508ba84cc4300e8 }

condition:
	$a0
}

        
