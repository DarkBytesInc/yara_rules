rule Win_Trojan_Kapod_8
{
strings:
	$a0 = { 46ec6463f7ea13a2ff90d956a537a40be5fb3232a5d6f787bd237eb67b8633887cf0104baa1f3f86516a5631423307ded234ab064f16e9476b54c343adba46ad0b98bc9cb906346a8cba524b8d00d756044d3f3303198ce489f539ae7c4c238a50d1dea4c26942ed2205a61caa6895d41a31086d3fac873d7af84252cbee0dc78c4c85d4ce746121012782503d5f318e3f0a0a8a346a }

condition:
	$a0
}

        