rule Win_Worm_Kamar_1
{
strings:
	$a0 = { 1f4f4d4f4f4f4b4f404fb0b04f4ff74f4f4f4f4f4f4f0f4f55482844cf4a236d4f5d234f4f494825744e4f4ff55f4f4150fb46826ef74e03826edfdf1b27263c6f3f3d }

condition:
	$a0
}

        
