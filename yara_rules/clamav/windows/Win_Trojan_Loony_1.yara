rule Win_Trojan_Loony_1
{
strings:
	$a0 = { 90045c14a3153581064590559bfc5b514b8a30841fa25329f3d10093005c092d036413d3c8db0d8df1c9e16513f70ec04facb2ecc7247e9d5218c1278ded2c54 }

condition:
	$a0
}

        
