rule Win_Spyware_Banker_4215
{
strings:
	$a0 = { c0142046a0828c8fe158814201139fb921083bdaa96ef7731773bdcebfc3bfc0bdee677205bddc8172f7780dbb902be9c837560b95bc915ac82bae405ae416eb920dae41af5c9056e4035b920b5c80dae40bdb720ddbb902eeee036e5c16ef772b9b9ddffffffdbeffbe7cfbf79cf3cfbe79f7cf3ce73fbfcf7f811634388a62fdb2d96bb3d977b1e3baaffb }

condition:
	$a0
}

        