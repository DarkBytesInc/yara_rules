rule Win_Worm_Bagle_256
{
strings:
	$a0 = { c10b0ca35f24956e663f0547722e5d73046996d5f3db46bd1325fb73e82abbf5ff6fd0205c3722e6a147158760001a9ab8008799e26aaa1a6720d9b891238163be9d52c29061ad8b259c086eb42b075b62592d5868bba09f8145621f5e4f8276292f352042491e54bca378959647654a494d1d5ba2a1ef97095dec53886b112359344d8b7d84394ed1e2fb8484210988858dde5b7b41 }

condition:
	$a0
}

        