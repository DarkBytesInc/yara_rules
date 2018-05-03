rule Win_Worm_Gaobot_66
{
strings:
	$a0 = { 5b7a0f929b039591b7dbbe457578db93ad2eac47c8686a8cb89a0245318a4c16bec0e790eca05f16fcd83eab0a2188eb222699fdeeb3b6ef3fbbfebd9d5ced99c36ec6bf53adafab5e1032eb1a0cfd10f75f81da5b3fac7871c8b50295fbbd5dcde8afb265d13da70854449d }

condition:
	$a0
}

        
