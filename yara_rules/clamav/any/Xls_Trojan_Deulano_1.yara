rule Xls_Trojan_Deulano_1
{
strings:
	$a0 = { 66204170706c69636174696f6e2e576f726b626f6f6b732822457370656369616c2e786c7322292e4d6f64756c65732879292e4e616d65203d20224e616475656c6f22205468656e }

condition:
	$a0
}

        