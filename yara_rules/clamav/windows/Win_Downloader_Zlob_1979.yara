rule Win_Downloader_Zlob_1979
{
strings:
	$a0 = { 8b1d6e144000ff9305070000898319080000c783460b00002800000080c61483ec0c80f2a48b831908000089042480f17880c615c744240428000000b6948bbb3b080000897c2408ff93bc07000089839007000083bb90070000007402eb05e9f4010000c6834709000067c6834309000076c683440900006980c2afc6834209000069c683390900005380f564c6833b09000044b1ec }

condition:
	$a0
}

        