rule Win_Trojan_Mybot_5595
{
strings:
	$a0 = { 7d14b328ceb1c9e890befb654f824dd233227f4a7e4349402fd869d745d96022e12fde65b30c6893013bb91ba02d52869e55c97e3007ef5fbb4ab277cbb97fef2dc2d73c3e30bd7eee434c111ba3a95027906fe62ba6ca5acccabb56e65dcacf }

condition:
	$a0
}

        
