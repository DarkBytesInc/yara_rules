rule Win_Worm_JuneX_1
{
strings:
	$a0 = { 696e652022666f726d617420633a202f71202f6175746f74657374202f7522 }

condition:
	$a0
}

        
