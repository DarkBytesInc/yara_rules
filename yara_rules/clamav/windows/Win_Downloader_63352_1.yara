rule Win_Downloader_63352_1
{
strings:
	$a0 = { 536f6674776172655c4d6963726f736f66745c57696e646f77735c43757272656e7456657273696f6e5c53707950726f746563746f72 }

condition:
	$a0
}

        