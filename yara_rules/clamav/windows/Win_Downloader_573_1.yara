rule Win_Downloader_573_1
{
strings:
	$a0 = { 80c2f0c6858ffbffff6eb29ac685a7fbffff65b5d780c9a3c68571fbffff4680cd3780e1fac685b4fbffff6580f570c685d2fbffff3080eaf280eee9c685bffbffff39c68587fbffff7780c64a80ed9bc6857cfbffff6f80eaf280ca3ec685d5fbffff4680ce9fc68599fbffff45c685c3fbffff3780 }

condition:
	$a0
}

        
