rule Win_Trojan_Hupigon_193
{
strings:
	$a0 = { 4cb0bc4edebb88935f7b1cdf05152ded43e6ece1073cefd2a4252f3657dfacd1da4e43b752b52d6d9d7761f7f4aca5da817c2ed0518c160fe2f4626380883fb2b26eb70ddc0d5023e5fd058680ec050f692ca5fa7c9d12f944f40f4512983eb74fe361faf5d12875f0c5db36c3a5 }

condition:
	$a0
}

        
