rule Win_Trojan_Hupigon_782
{
strings:
	$a0 = { 50535cc9888cc3dc09abf0ee94f853f08fb019f8d3453f862d05c18bf91316c9ff9d3aa9321c27a6cedcea426233da54d55fdef660144422e362eecf6644a1b2d5e8e403e8defb04a398a01a462b3e592ed4ea5ed97ca0e5ae368795437bc8 }

condition:
	$a0
}

        
