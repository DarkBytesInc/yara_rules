rule Win_Trojan_Delf_1234
{
strings:
	$a0 = { a0c01490628083e923e0ac40438044e79207183b9b775db7bf85ddef73bafe1dfc06f733b902ddee40bb6ef217d36056d7916e2c17babc905a401dd7202d70077ae48bab901bd32035b901eb73920a64637ae40bae641db9724aedb915b6e51bbf8f77b99bffffffb7dff7f7f7cf9e73efdf9f7cf9f3cf39ce7edfdeffc217321069cc16cb65aad166b5920b }

condition:
	$a0
}

        