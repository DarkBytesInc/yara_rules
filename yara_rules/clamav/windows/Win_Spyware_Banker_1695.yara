rule Win_Spyware_Banker_1695
{
strings:
	$a0 = { e41d55316b3e6339fa12010dcf79396cf4c7b97584d17d0fd8bdd1c9e6a6cb35519771d5e5ae562fa26979b051f7ca260827d1251d6a0af6aa9352730b009cba874fccd6e244c371e668bca98700ba5c95b2b663d75fcdfbffd2788f65e19d826ff847e311843471f801030a249721145d0ac7825af666f0d8cc544459d58e575a4fc853ae3d09a7693056ca4c0a0297132a6e13 }

condition:
	$a0
}

        