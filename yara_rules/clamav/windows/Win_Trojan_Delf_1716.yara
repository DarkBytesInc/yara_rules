rule Win_Trojan_Delf_1716
{
strings:
	$a0 = { 2c2f6367692d62696e352fbb883c0d9c16e2426572663fe051cf226e3d08266c617396ce9a16746964060348b4206eeea1521d }

condition:
	$a0
}

        
