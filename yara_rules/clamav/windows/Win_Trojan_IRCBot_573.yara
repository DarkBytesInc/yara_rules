rule Win_Trojan_IRCBot_573
{
strings:
	$a0 = { 48489f7cad5fec3666f0c3b47d4bd17cfc85f6798b994fb3872865557fbdea95ba0675d0b81a04b7a8053090d3ec730fc98ed1777ee5cb078f9796c4b6c4b6df289ab9d03106586365cb7d91de0d8ce5781fb44dcc2192e37b9473e08bf9374a1645d424a212f1850ad6c3068e4113f420c8bd24822195ca1285de377ecbd35e7cb7c16d5d398d5894073885b0b4e8dd005fbaf493b3 }

condition:
	$a0
}

        