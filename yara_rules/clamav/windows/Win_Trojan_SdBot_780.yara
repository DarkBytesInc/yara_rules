rule Win_Trojan_SdBot_780
{
strings:
	$a0 = { 4690c76265672e875498cc0c26d7e6668560746968ebd74d5ddcbae988d545e6ee2f7bde683c784d307bb825a85623089fc41d3c7181c864764e7d198ca043801df87cf676adcecaa50c9bbe10950a771d563e7d2a0a010da005bd993bdb28b4620f96ca5be297bfdd13f0036eebba2af930eddadeb1ca27e5e6f638e67286b025186d53ade9f4733d7631bedd6daec01406e7cd11c3 }

condition:
	$a0
}

        