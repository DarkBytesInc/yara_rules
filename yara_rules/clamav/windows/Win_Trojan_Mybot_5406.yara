rule Win_Trojan_Mybot_5406
{
strings:
	$a0 = { d78512daf0560a0bf5f64be80f2c1f6ba8e91fe11844eafd83c40d3b0015859a37e28bd93ad8de4e5e9a195ad6d96758d4736751a48ceeebd7105faf197d92e33c7612d4f355d38e03b24e1170abd65e6480fba22273bc936e7a2509a924dd516b7d01b2fc626afe70 }

condition:
	$a0
}

        