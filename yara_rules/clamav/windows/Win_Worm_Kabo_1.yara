rule Win_Worm_Kabo_1
{
strings:
	$a0 = { 500052004f004300000000000c0000004d0045004300480041004e00000000000a0000004100560041005300540000000a000000450053005300450054000000080000004b00410053005000000000000a0000004e004f0044003300320000000c0000004e004f00520054004f004e00000000000c0000004d0043004100460045004500000000000c00000043004f004e0053004f004c00 }

condition:
	$a0
}

        