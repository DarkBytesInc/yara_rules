rule Win_Trojan_Sirefef_5
{
strings:
	$a0 = { 3900310049006f0034007400320062006c006d003600000000001e0000006a004d005300510041004f0046007a005a0050003900380036004400450000002400000067003000310031004f0039007400450032004f004e0072006800380054007a0074006a00000000002400000053006300430075003300 }

condition:
	$a0
}

        