rule Win_Downloader_1021_1
{
strings:
	$a0 = { a00273b2fffc070f10e1b1f3055e8d2c34e8b59d7b1f07e6e0439cd090fbae0b23f2183590db59abfadaed754396ad4ac0874cfa8c2c4cd2e90722eeb55454dc58f8f52ee9cac57b68d4b5f83a720c8eb1f8a5b2f8baf8042d88af38 }

condition:
	$a0
}

        
