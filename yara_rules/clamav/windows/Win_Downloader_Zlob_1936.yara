rule Win_Downloader_Zlob_1936
{
strings:
	$a0 = { e50c9181ec9400000081ecfc0c0000b49b89e380c2e3892500104000a15560400080c1cc8983d9030000a1596040008983820a0000c783d50c00000000000080c2ad80c523c783390a00000000000080c61ec7832602000000000000c783c70100000000000080cad6c7431400000000c783b002000000000000e81111000089836b02000083ec0c8d83b402000089042480e51dc744 }

condition:
	$a0
}

        