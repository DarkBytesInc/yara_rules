rule Win_Trojan_Chinky_1
{
strings:
	$a0 = { 683b5273ad735073e473507351cb4f7386cb4f7351df4e7365745073266e5073736e50733f7c5073cf994e73ee7d50738e5b4f73e5a04273e2994e73e0984e73244650731b7c5173048851736a7c5073917d5073930d50732d8e50735dd05173fb0c5073e5dc4f735c545073c2404f73be115073baed4f73a4354273de6b5073e26c5073661b4f73231b4f739a604f7300000000000000000000000000000000ff2534104000ff2508104000ff2564104000ff258c104000ff2514104000ff25 }

condition:
	$a0
}

        