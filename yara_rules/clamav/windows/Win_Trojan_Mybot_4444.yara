rule Win_Trojan_Mybot_4444
{
strings:
	$a0 = { 497bd16a2b943997810656710c81326d58a8026082fc92208adb3722c1bc2267b1e9c68dcb6ab1f5768dec5b8b293155d93c5aa968366442644c8853373f8bee2031b31b7b859e067b8ea705daa59bf2a0db57dd1c48143d1a2dcd8465be82839f889189be3cca58031dbe3d2b7bc50c26f403ed67d812fc69678b195589cb2be26394c660e212cd1ad2c5216a7a91312380458e }

condition:
	$a0
}

        