rule Win_Spyware_5460_1
{
strings:
	$a0 = { 688c2a87129e45554230a714bd46f6e7bce288324de9c3531d611e62fd3ca6c436dcb12bdd5276ef307433eb0ac1f593ab0c693b1b91f02df2e2834741bec154a9cb5981773e4c6f6d4bed6327da89863927e16e12e300571f765eb279ff9cdb6e703021cb48c6a5c8ade3ee4fa553ee19e265dd1f3750b8146751b9eb3f3607df5c0f581406cd42aba6 }

condition:
	$a0
}

        