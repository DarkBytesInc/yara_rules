rule Win_Downloader_Banload_1567
{
strings:
	$a0 = { fc81271001e7b6f5f7f4b09e838b8c82eaea01c00a03db9bbdb7a9bcdc83a4a0b15e80115683fccecf89a1a9b511c5e0c33e2dfce8c4e084b9bfe5d8ded8de5e580006dbacad2c54d70c923040fc98d7fefdfcea931880619b054dfc67c8125f83c4fcc1840120fc77251e020b6d97ac2c0134fc571d3ccb85b5e55382 }

condition:
	$a0
}

        
