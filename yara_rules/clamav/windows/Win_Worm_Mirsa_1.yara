rule Win_Worm_Mirsa_1
{
strings:
	$a0 = { 6c004e0061006d00650000004d00520053004100000000003c00120001004f0072006900670069006e0061006c00460069006c0065006e0061006d00650000004d005200530041002e00650078006500 }

condition:
	$a0
}

        