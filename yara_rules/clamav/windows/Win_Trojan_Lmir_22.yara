rule Win_Trojan_Lmir_22
{
strings:
	$a0 = { 764d6f6e2e4558450000cceccdf8b7c0bbf0c7bdb8f6c8cbb0e600000000546170706c69636174696f6e00000000cceccdf8b7c0bbf0c7bdc6f3d2b5b0e60000000054466f726d310000ffffffff08000000c4bec2edbfcbd0c700000000ffffffff06000000cac9befacce5000054664c6f636b446f776e4d61696e00005a6f6e65416c }

condition:
	$a0
}

        