rule Win_Downloader_Small_2179
{
strings:
	$a0 = { e90189e50cb181ec9400000081ecfc0c000089e3b0d5892514534000a12860400080f6548983c5010000a12c6040008983a1060000c7839c0c00000000000080ed1e80f520c7837b0c00000000000080f230 }

condition:
	$a0
}

        