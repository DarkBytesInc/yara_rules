rule Win_Trojan_Mybot_6674
{
strings:
	$a0 = { de8b7a90340b8135dd0b7c7d8f1c93658938b8490432764aa11ae0f43f6fe54ad8061b370bbf1fbbb1a46cdbf8144018593d7de0da0dc90c8e175b22a371357e255e7e903c2057e8acac8bbe13d67fe8d3f3869f94eca7a45d4134a40ef5534e815a46e6448b7b64172d1a538980a29d82f2a05aef6606fb24f6206a0faf965869211ff199918526ebc82b3de935493a1e4a9ebdb968 }

condition:
	$a0
}

        