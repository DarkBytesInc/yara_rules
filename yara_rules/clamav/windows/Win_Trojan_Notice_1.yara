rule Win_Trojan_Notice_1
{
strings:
	$a0 = { 656757726974652022484b45595f4c4f43414c5f4d414348494e455c536f6674776172655c4d6963726f736f66745c57696e646f77735c43757272656e7456657273696f6e5c52756e5c5a696f4e222c22433a5c57494e444f57535c7a696f6e2e6a70 }

condition:
	$a0
}

        