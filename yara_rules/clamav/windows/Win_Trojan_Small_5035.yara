rule Win_Trojan_Small_5035
{
strings:
	$a0 = { c1e80233dbc02da02c89100f869900a15a2c104d90008b158c5b2693d32433df22b2a0942420b93fe072ae898dbcf3ab8b4c2f38ac139c20511104ff1514910d0044f085f6744c8d54241c526a04ba89da091c505631fa0b540b74368b14680401b62d364d8c51528aa5a4052b8b450850906e3b3d105604a7c7b20c10031b6001433bd80f8267ff5cd0c288 }

condition:
	$a0
}

        