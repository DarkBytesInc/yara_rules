rule Win_Trojan_Small_3694
{
strings:
	$a0 = { c5583945bfafcb05d72975446fc14918af59b6ecf75c6104f21d7a5a6e31a254c5c36257d74175446fae497672596187337260799371601a7769a104ceb7be5fc81cb85bd75971046fc36903849171446fa9601aab69a104fa49cc04d97cb76e6f5877587f9961892fce938fac8971446faf60 }

condition:
	$a0
}

        