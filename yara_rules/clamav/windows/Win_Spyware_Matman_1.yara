rule Win_Spyware_Matman_1
{
strings:
	$a0 = { 77735c7678642e6578650000633a5c77696e646f77735c77696e33322e76786400000000558bec33c055681b4d400064ff30648920b8b8504000e879e8ffffb8b4504000e86fe8ffff33c05a595964891068224d4000c3e970e2ffffebf85dc3070000002c4d40004c3e40001c3e4000b43b4000603b4000843e }

condition:
	$a0
}

        