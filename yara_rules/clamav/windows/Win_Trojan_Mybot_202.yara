rule Win_Trojan_Mybot_202
{
strings:
	$a0 = { 9024fc2587e97c90d40c5c4321f2241f9025f820b5eadc76a70cc44a4fff45c023340abe42414e49434ba85c0ca84f10504552e92ce4a80cb92c3d257e8892a063b7c65c3a6f520c28555324a8028a57b5f7170c0670617906afcdca }

condition:
	$a0
}

        