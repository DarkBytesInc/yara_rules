rule Win_Trojan_Fakealert_108
{
strings:
	$a0 = { 0c05c59e4a3d7731431be9f6033993d91cf4e657c30f5fdabd363825f41a8dd6eb115b0f88105dd69bf2a835d618a3d7f73ee230b7fb7bd5855a0547f77576552dfa294ddb204cae831057d7f64ffeaad53ca44e483dfb88bb7c9644650c7246bebac3a8 }

condition:
	$a0
}

        
