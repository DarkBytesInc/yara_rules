rule Win_Trojan_Bancos_1548
{
strings:
	$a0 = { ab33ccceef10a9bee6bc84622e601f5c7ecf0b26b671b4952b5e525f1e88374ac457ec3faf45deaf97a7eff6ccaba8532344a3a1e77873ae281d22bc314103ae7571c4105d6e44d44639e5aaf8ab0375a712295b102a95e680ddb2479ae79929bf94b189a00cf98f983f4fc5e383f27deb74baa00831193583484d51b8eb031bc8a5eca2c5b60260a3642b8a8d877af5593721afa1b6 }

condition:
	$a0
}

        