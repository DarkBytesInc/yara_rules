rule Win_Spyware_Banker_5702
{
strings:
	$a0 = { 97ffa98154ac74f737ce3959b4b03dafd2902c71184a5bed6b88b46c0fa9d0d453a68ec83abfaa50379632b26d4d17af260bc998254232a78ad8f082846dac5ef4a0eb58985a5ec53e824f2d3d695a8c33a0e9338b8ac53a6f4b }

condition:
	$a0
}

        
