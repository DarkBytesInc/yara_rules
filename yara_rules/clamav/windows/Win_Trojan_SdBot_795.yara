rule Win_Trojan_SdBot_795
{
strings:
	$a0 = { 14ec73616c0b0e0044287c5b257907118d2b682600ee07736b7970b6c56e48b107c66576636d0bb030535b07333b4c5b1b72b16e07621fd80c6549e31b0d64b07907646958a32da1b16ed78465d25d07646f86736461670b620bcf67bd6507b80361764dc3d67e72077e6368776fcc872df4709f07727265916e610fc2670eec65730b1d6661cead07d9657a0fb36f48a73077ac6fb3 }

condition:
	$a0
}

        