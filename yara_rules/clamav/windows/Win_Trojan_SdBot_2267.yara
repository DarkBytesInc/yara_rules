rule Win_Trojan_SdBot_2267
{
strings:
	$a0 = { 871f06789ecd7b3a0ca0cb558562bb85dfeef3f71b1beaf981ba572d543db58fc71f507d013d2e15241a792be9a1079c75b614212afeef31dfd6c29be871e69ae8e05c8e316d3d1f994a1c150047724a4e1f98100ed58f11bc6965cb2bbd7a8296198dc1b5610d3f143e5d58ea0397ae1b1a4e8419ea87cc40b44e7c1817128213fba18301b8a67c5d3e }

condition:
	$a0
}

        