rule Win_Trojan_Beastdoor_63
{
strings:
	$a0 = { d316ff6f13d7fdf94b8c155c6cba18b2356d8ecca9d282aa059789048be58b1d881ac069828d29383d7ce7f88ce3f3ceef469800259cad2db9deda6dadfa4b374d5327212a5568dae89655c8f9022c131b2d6c1d1a5ad5765a7796b3296ad60ca484b7cfbb73a0e33f98a5cfbdcff7cfe77ddee7bd8f939b10fa8117a1 }

condition:
	$a0
}

        
