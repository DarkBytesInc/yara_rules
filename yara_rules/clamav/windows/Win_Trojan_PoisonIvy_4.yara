rule Win_Trojan_PoisonIvy_4
{
strings:
	$a0 = { d8bcefd3dac8cbddced9e0f1d5dfced3cfd3dac8e0fddfc8d5cad99cefd9c8c9cce0f5d2cfc8ddd0d0d9d89cffd3d1ccd3d2d9d2c8cfe0bcd9c4ccd0d3ced9ce92d9c4d9bcbddfcfcecfcf92d9c4d9bc00000000000000000000d2c8d8d0d0bcddd8caccdddfd7bcddd8caddccd58f8ebcc9cfd9ce8f8ebc }

condition:
	$a0
}

        
