rule Win_Trojan_Hupigon_131
{
strings:
	$a0 = { 79441dc4e233762edb7cedb015d6f194c84786eb64c42aee1cf193c1ef4e205ffc940dcbbdba61dd41a95ab64005e06be0ab1a32a8e4136a61dfeca3d3d02ba3dbfc1dbef5b37dae923ee1ea742244694c2efab3f0b70a74c661 }

condition:
	$a0
}

        
