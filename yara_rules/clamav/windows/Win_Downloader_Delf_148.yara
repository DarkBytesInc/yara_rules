rule Win_Downloader_Delf_148
{
strings:
	$a0 = { ffb80bf82d88262d2897dd15f75490e9122e5356b32c0d3fc942e0ba0266fc24fb52a203b90627c0a768285f585ed34e13845a44106871741c703a2f406261646d656ef9d96ca8260e8815802e6e657466691e726d734e636fb5113c3f67286610c8138c4c6f206e49539fbb79ee44f5dc61627c6ca40e2788536f006674776172655c4d90b376f873de1d83524153209b75c7d3 }

condition:
	$a0
}

        