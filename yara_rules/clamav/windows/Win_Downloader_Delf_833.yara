rule Win_Downloader_Delf_833
{
strings:
	$a0 = { 87f1dff7f7d08db045ef3f846c07b52f8c0ddf57a3c9fcec2b60f885075b4de63c2f7974917a6301e4127c2b6cc3c88706d2a929367407bcf34c3f71ca84ba5b66c166f9c3b1f24913aad2a13abaea2c0e1ef7e446768830b2dc5cc29bbab162c2e8e891ed5705f89fb179 }

condition:
	$a0
}

        
