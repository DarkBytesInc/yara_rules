rule Win_Spyware_Banker_2785
{
strings:
	$a0 = { 8f7cf51014b01274e2330ae91665afa384cc8deb1c016e63f5755623e5b5c388e3127ae2fdee428bdaa9c27fedeaefa5abd95580dea5b6f6e3e94430f9f373ff0a7ce3945922ece8254e6bf2636fb93e1cb6ecb4ddf5941166a3c5c63404119a154a8722 }

condition:
	$a0
}

        
