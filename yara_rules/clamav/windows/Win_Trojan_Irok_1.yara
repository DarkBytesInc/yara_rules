rule Win_Trojan_Irok_1
{
strings:
	$a0 = { 3375813ee80f009ae8f9ff9a9ceb019a5980cd01519deb019a1e0e1f8beceb019afa33db8ed3bc04008f06f9038f06fe03eb019a0ebef103565e178be583c410fb1f59e8c6ff33db1e8edbc747040000c747060000fb8b1e6c043b1e6c0474fa0e1fbe2001b98702fcb20580 }

condition:
	$a0
}

        