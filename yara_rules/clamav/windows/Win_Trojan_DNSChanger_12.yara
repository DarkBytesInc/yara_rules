rule Win_Trojan_DNSChanger_12
{
strings:
	$a0 = { 611f0ae2b3a31154e4a317bf71aa36516e824615e3e1f31da8c93666fbf1cc1b6fadc0546eec43157be6cec660fe13a8c4febfca6aaad67c7eebc0d92e1fce53e4a7c06ae6bb0055f36b3659a06bac66c4febf6ab2bc0055beaad6947febc004700a1fb0376e16e05a2cade96eabc0e1f317c0546e7246c16daac0e96eabc0a46dc07c65aeab4312ebaa }

condition:
	$a0
}

        