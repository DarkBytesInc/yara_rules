rule Win_Trojan_JS_217
{
strings:
	$a0 = { 7a3733747a33647a32327a3235 }
	$a1 = { 2869293d3d227a22297b73313d2225227d[0-19]7d723d722b73313b[0-25]7a282429293b }

condition:
	$a0 and $a1
}

        
