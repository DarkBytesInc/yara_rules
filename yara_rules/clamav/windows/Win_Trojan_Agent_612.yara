rule Win_Trojan_Agent_612
{
strings:
	$a0 = { a105005a4f4e45414c41524d2e4558455746494e44563300cfdd593245425343414e73b3007558565353544154eb6917964857ce029e7345434f4d529785ea65563430c30b75804554545241593935cb }

condition:
	$a0
}

        