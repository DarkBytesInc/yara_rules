rule Win_Trojan_Mybot_7391
{
strings:
	$a0 = { 29ff7098b1cbb605c2dda47cd19dce1b4d7afa9ad2f7c350f989ae8fb7ec3cd90a4c1334ec9f3628262576bfef558a2cca2a84d697f962ae7915d407f896cbefe1c29b1800c5ffe26a9f70a44d443d668649c9cebd9af8aaa43b088f95d07db81cee0bd041c1dd39f27e3477f69554d8465d39d5b42d08ccc2667404912ad146531302e8e413af129e5815dae12068f16b51766e3d0d }

condition:
	$a0
}

        