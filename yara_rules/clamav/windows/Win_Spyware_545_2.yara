rule Win_Spyware_545_2
{
strings:
	$a0 = { 2aa1231d4171be6c6729c7110ea2a08e7f7b0507d0d89e410989ec9e0f1a0380c3227b705e3156daaed3c59b24669e5f9b8cd8d8a41d7a65c6457738c945c5f1768deb57399574b03652bd7a22245842e422e8552e78042ca59321c0f8114c80ec5be8c1efa9dc3a085cc87d0d6624baa5073596a946fb5275b99a2c05fd0434b948813868644a3cd9ae1a78b7af151492c47c87 }

condition:
	$a0
}

        