rule Win_Downloader_VB_9
{
strings:
	$a0 = { 6e00000008000000410042006f0078000000000010000000570069006e004c006f0067006f006e00000000006e00000068007400740070003a002f002f003200300039002e00350038002e00380030002e003200340034002f006e00650077005f0069006e007300740061006c006c }

condition:
	$a0
}

        