rule Win_Trojan_Downloader_119
{
strings:
	$a0 = { 3a736574713d64662e6372656174656f626a65637428227368656c6c2e6170706c69636174696f6e222c22222922293b646f63756d656e742e777269746528223a712e7368656c6c65786563757465666e616d65312c22222c22222c226f70656e222c3022293b646f63756d656e742e777269746528223a656e6473756222293b646f63756d656e742e777269746528223a63616c6c6175746f6578652822687474703a2f }

condition:
	$a0
}

        