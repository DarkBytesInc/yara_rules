rule Win_Downloader_Small_2215
{
strings:
	$a0 = { f55589e580f41981ec9400000081ecfc0c000080ee2789e3892583514000a1286040008983fc050000a12c604000898397010000c7838d03000000000000c783e80a000000000000c7830409000000000000 }

condition:
	$a0
}

        