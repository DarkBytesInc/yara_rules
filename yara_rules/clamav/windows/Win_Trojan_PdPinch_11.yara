rule Win_Trojan_PdPinch_11
{
strings:
	$a0 = { 802920454105191f05220508044d792068817395a5bccde71bbcce657e1cf806f999cc816f3790376f39a0b6ef702b6ba82f160bcadd482d21e976e405ae02ddb920dae415e3920b5cd0bb6e480d720376e40b979906ddef2036f320dbbb80b9732ddfc37fffffedf3fbf7eebaef5df7d77e75df7e6b5afb7ef7fc11834409a52ef07c1f0361aff044487cef }

condition:
	$a0
}

        