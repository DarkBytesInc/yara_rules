rule Win_Trojan_IRCBot_487
{
strings:
	$a0 = { 5d76401aac1c1f47fc2240ec70937847ccea15d482e4888a6dbaa26b818e59189a9dc0e3d2867f23b7f9968a4748d5f58c95c508e89a19405dcaca1466c685a79f3b4f6ee279d11672274a254ff308fa702456515a110f2dfe67e9c9b8707c3fb58d5aad7da0814d134d600320a65ab51ce75ceb75f8dc441920280dde9609b3c7eb9d6aa17d6ba402bec479d896318e675e29052696 }

condition:
	$a0
}

        