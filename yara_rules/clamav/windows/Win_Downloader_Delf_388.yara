rule Win_Downloader_Delf_388
{
strings:
	$a0 = { 667733322e657865000000ffffffff0a00000077696e7570642e6578650000ffffffff080000004d5357696e75706400000000ffffffff2e000000536f6674776172655c4d6963726f736f66745c57696e646f77735c43757272656e7456657273696f6e5c52756e5c0000687474703a2f2f7777772e706573736f }

condition:
	$a0
}

        