rule Win_Worm_Stration_371
{
strings:
	$a0 = { 6d731c7de038c4558bec2d8cdea8df10d24962cdbb6dd98a1e87be5c34f48383a94167c6a49d2cdbf5bdf80ad3e277ac07295d23ede18ccc5835df30bcb605e364717cfbbd7d1745b98af98d96e7f56230c2f89025f3233f4e451b39a1da8627 }

condition:
	$a0
}

        
