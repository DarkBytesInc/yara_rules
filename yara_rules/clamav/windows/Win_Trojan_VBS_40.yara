rule Win_Trojan_VBS_40
{
strings:
	$a0 = { 7574652863727970742822d6e0f1a5c3d6caa5b8a5c6f7e0e4f1e0cae7efe0e6f1ada7d6e6f7ecf5f1ecebe2abc3ece9e0d6fcf6f1e0e8cae7efe0e6f1a7ac888fe3f6eaabe6eaf5fce3ece9e0a5f2f6e6f7ecf5f1abf6e6f7ecf5f1e3f0e9e9ebe4e8e0a9a5 }

condition:
	$a0
}

        
