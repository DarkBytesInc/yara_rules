rule Win_Spyware_Banker_4656
{
strings:
	$a0 = { e913bd19fa62869aeb9980a35ccc1ae11898c2a63b292189dc51451b826525cfc2d33769b380ba09f89c1bc8693483da9dc4d54f787c6585f6e85570f262263a6f95d8907bfa91e002f3b3cc96cd2b2b6e8fb44cd844c2790da805f9f4dc2517b67b251eac00bf12de9c3cd31488441bf7c295cb0564b1b056cbe647cb0caf86b39dadd04aa28497424610fc0621a57947253fb440fa }

condition:
	$a0
}

        