rule Win_Trojan_U_104
{
strings:
	$a0 = { 8b45acc9c35589e583ec6883ec086a00ff7508e835feffff83c4108945f4837df4ff751083ec0c68808c0408e87cfdffff83c4108b450c8b402c83e81c8945f083ec046a }

condition:
	$a0
}

        
