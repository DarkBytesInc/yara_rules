rule Win_Downloader_Small_508
{
strings:
	$a0 = { 67b0648f3e5328fc238776756e576a5979fce9865d6e7b8ec52e4077d80049ecb5b42c672316c729b3735c1c96cf112c0def740c720a9b816aa12577534f4654d6deb5c15245d04e31e55c09a3e8174375726eb758e5465c4272316c386e2048703330526300c002dc7b4135333637332d4538430b009205412d313144394344392d3030393032374af70438303735427ddb }

condition:
	$a0
}

        