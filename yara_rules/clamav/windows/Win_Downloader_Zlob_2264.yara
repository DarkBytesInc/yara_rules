rule Win_Downloader_Zlob_2264
{
strings:
	$a0 = { 84aede49e3c53b765e562cbadf85ca4516685fb04bc8f3ee0d3abcbc6c1271b00f7eb881566b6153b3961d6d0de48cb9ca9566ca96e1bf83f6573eca15e196a969c42f166d9f896ee6972266b08b58084b022797fcc55f2e53bd }

condition:
	$a0
}

        
