rule Win_Downloader_VB_308
{
strings:
	$a0 = { 2a005c00410043003a005c0044006f00630075006d0065006e0074007300200061006e0064002000530065007400740069006e00670073005c0052006f0067006500720069006f005c004400650073006b0074006f0070005c004100500041004700410052005c0064006f0077006e006c006f0061006400650072002e0076 }

condition:
	$a0
}

        