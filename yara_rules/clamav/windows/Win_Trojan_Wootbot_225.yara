rule Win_Trojan_Wootbot_225
{
strings:
	$a0 = { 48134c310c3b2d4b82a2609bb4e2653862e31e1ae881f8b021368462895ad9bab8d6530e3b6254823020c9a409cba9261dcb6566bda462b2fed5d59dd1cf45c6d68daa339af27a57d08b50b2449eb361f74eb2d297acd8bebd23c7ea75eeb26a20c0b8d8ab9fc3c24cf4610bf3d2d208a28f7ca0900331ab53c50d19d3cbb22c590f13ca4312f9d9a71dc7835d045615604afdb2231a }

condition:
	$a0
}

        