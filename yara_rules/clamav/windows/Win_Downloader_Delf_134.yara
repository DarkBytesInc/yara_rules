rule Win_Downloader_Delf_134
{
strings:
	$a0 = { 697a2e62697a2f642f322e657865000000ffffffff0a000000686f737433322e6578650000ffffffff2e000000536f667477 }

condition:
	$a0
}

        
