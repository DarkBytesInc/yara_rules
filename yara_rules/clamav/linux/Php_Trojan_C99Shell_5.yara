rule Php_Trojan_C99Shell_5
{
strings:
	$a0 = { 37696776346178713764716f766c32666b7a636277616861676467666e637962697a777a76636d756764786e687a32756e6367306b707a346e63673d3d223b6576616c286261736536345f6465636f6465282471626462353165323562663961376633643234373530373238303364316333366429293b3f3e }

condition:
	$a0
}

        