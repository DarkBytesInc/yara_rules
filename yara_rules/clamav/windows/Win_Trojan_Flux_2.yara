rule Win_Trojan_Flux_2
{
strings:
	$a0 = { a50865c83c209456bcfbadf8d2cc5860b8f0b41b8119ed0587cb8c7cf8c1c130b3a8085962d143b08c64cd16820b0ee2a623e7a5ae32482a65e66e09a31d82efaad974a100506932262759323ecbb0c1d56681f40b00c1354318735c1d0be2b87e93ae94f1bb81dec0a4121bb81bda375d0c10a5a12dd1521215d558f9f276cb5b1e07ee }

condition:
	$a0
}

        