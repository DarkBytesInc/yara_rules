rule Win_Trojan_Keylogger_90
{
strings:
	$a0 = { 9a9a934041360ec18d1e9b177fd01f313fb4eb94a5cf217f5ab245911f9eff50021ca71ca0031261850ecb3febf4c54f6e4ec5e1b5170a3a683688e2961ded7bd8d11d860543c69382d046d51e119554fd42adc467d2a7010144a73fe2b648f31fbe9afd16267eec659ee3c3653699692e5e96a02485559148b6266c6e812a502238add935c58ec1d70f9ac8 }

condition:
	$a0
}

        