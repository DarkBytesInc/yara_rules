rule Win_Spyware_Banker_2623
{
strings:
	$a0 = { 96f2f36e339f410d487c7a7ad3036c7149b9f737b00ffc48c8d4bf38a8f7187c3cc2fce3db8337eacf7e461aa69cb730238b753befe152fd4548fc413bd0fbddb46466d05846fb2fcad062d3bc89fa38071cfe157569d20fffa6a6f1646c3df73fc7 }

condition:
	$a0
}

        
