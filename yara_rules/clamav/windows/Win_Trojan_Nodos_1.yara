rule Win_Trojan_Nodos_1
{
strings:
	$a0 = { 01be27011705b5026806be26018bfe8b0e08018b160201b8770150fcad33c2ab8bd0e2f8c2de1eebd38d0f478c77f437c6fe41fc0f4d0cbd597853cd7c488d0f478c7ff43f85ad7f55838508 }

condition:
	$a0
}

        
