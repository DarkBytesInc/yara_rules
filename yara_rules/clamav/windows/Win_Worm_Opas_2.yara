rule Win_Worm_Opas_2
{
strings:
	$a0 = { 4a057936e78d209a909a8e99775ae35b4d454d4ad388ee8ed63d8c8c6a786b2b64bf30a43906e112cbf407bbde09ac200c019cf04208f255e902d39f4ffeefab5a8d0c6ce13a173ea08135f28e6ff124f31f3fa9987aeaa23d0e6edc11f6f177a64a0b5cb40e79eb08b52eef91ef3e80bc15c19a2d3c0d1a1abc308b1e312fdf1826fde6d5fa1b85693fe4 }

condition:
	$a0
}

        