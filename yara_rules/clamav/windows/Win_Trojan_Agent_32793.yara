rule Win_Trojan_Agent_32793
{
strings:
	$a0 = { 1cea658b1c91a9cca7f569c84e92eeb170b61517ad624ecf6df95d505c1d0af941a7bbf387f3e29c9582bda0b4633c2d71d0675da890ae1ad4c4bb50a3e51fb7322158a78596334e127c2b82838d4ccb6a56925be21f4afa252c61159c59c63f0c81ff26336c6d8461d066e7e5f1a35fa7f463f3b6e5dac129b88c91b9485135a1a36176397473e3226a38a2c21ac53c31b1fdde }

condition:
	$a0
}

        