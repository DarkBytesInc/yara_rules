rule Win_Spyware_Banker_2670
{
strings:
	$a0 = { 6fa3d3d8905b8dfc64def6ae0d8d31e2dc91082de75f7d26f9af1f16a2c54c68fe7f4f7c7826b0652cc4ca95d6692e3702d03f80f867455f17e93d1ef0a640ddcfc3270c44026ceac0cbc2346c882d22d7de571c117546e5fdba670fb949ddd11faf }

condition:
	$a0
}

        
