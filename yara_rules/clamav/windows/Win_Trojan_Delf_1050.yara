rule Win_Trojan_Delf_1050
{
strings:
	$a0 = { ce1b70d62c0d2adb361b4ae3cd5aebb390e9e4dbefca90ceef07ffcfa51a59da0552121b64e1a1a86319778bed74f75426e2057d6319df9bde73023fed0a13041b5aeb56a9e693b50b19eb9f4d0549d863e59b07efff069cd78583515f6feeb3dc19ebdb }

condition:
	$a0
}

        
