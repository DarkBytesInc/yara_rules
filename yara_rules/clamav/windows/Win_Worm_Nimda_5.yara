rule Win_Worm_Nimda_5
{
strings:
	$a0 = { 2b7b4c6adc194c7b73b5939fdb3ee7ad77f5bc5b9e4f7822e3431b4a1763a20afa7d264cd8d1beacd718872efbae3108a0e3037f8f2c8de041662e264648ee8319bbc345fc3dd8d8963197bc750c4d40104dce88e1babe1b7d8511318496b5fdf1ab5ccde9868d2fc3a224a441bc597abdba9e952b20fe10add1f9 }

condition:
	$a0
}

        
