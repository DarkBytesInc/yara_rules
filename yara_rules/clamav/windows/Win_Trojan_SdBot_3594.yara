rule Win_Trojan_SdBot_3594
{
strings:
	$a0 = { 2e6874ff75fcff15ec3085c0742d8b4df3804c00fc8b41290145f85051f0fb68bd0937e75350c234019dd71c8300868562408b8378210075b46aa158009935405d4315f0ae17e03250e87f0094ac501edb225cf8008af5632668441b007826f82c3b45145f5e5b7f06837d10168a5b8c15750c18d1991008ab04734c1fd1c9c3a006db09007b5733f66a108d }

condition:
	$a0
}

        