rule Win_Downloader_Swizzor_282
{
strings:
	$a0 = { 7e9022eef71691ddf225f29a23fd47b9b2eea5f8034966bccecf34d8280dabe08a6a6ef6f16a49e0ad9c8849443f4746bcf154a7a2b699d0ff8140cccf502e290f5dbe540b1ec9a8a81ade330b9eefa4fb0e9bf819405b886b582c6415475d368b812c2793edf557eed56630b6a0 }

condition:
	$a0
}

        
