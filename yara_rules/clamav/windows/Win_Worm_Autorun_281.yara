rule Win_Worm_Autorun_281
{
strings:
	$a0 = { 04f801c10ef7efffe7682e8ace8b89d352e827025f6890a10d47ec1fecdf3effd689c581c005a0ecdd221f4a925340f6 }

condition:
	$a0
}

        
