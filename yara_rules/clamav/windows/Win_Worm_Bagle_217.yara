rule Win_Worm_Bagle_217
{
strings:
	$a0 = { d13296ce332b2ca25f372017531e995803077d64ebeb6ab3e90507cdec08ab9c0b8fec8411ad81df648fa67cd0e0044366700c4ceabb38ce771d2ce46a96502709992476327764627800e1770b7e13249078bdbf5d72d1bb154763fca2ae08fef5e7a753fba9642ee208706e9c62b9c0f8af63542ed8d6833f3dc52352501ca4636e1d542cf013cc7c953c89733e3a8d49cd7c448e2e }

condition:
	$a0
}

        