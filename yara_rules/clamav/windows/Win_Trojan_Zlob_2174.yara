rule Win_Trojan_Zlob_2174
{
strings:
	$a0 = { 5c00000000536f6674776172655c0000006a656374735c00007365722048656c706572204f6200000043757272656e7456657273696f6e5c4578706c6f7265725c42726f7700000000536f66 }

condition:
	$a0
}

        