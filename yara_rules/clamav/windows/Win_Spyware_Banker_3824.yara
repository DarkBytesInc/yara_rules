rule Win_Spyware_Banker_3824
{
strings:
	$a0 = { 30050831a820a323f8522050e01139fb903841ddb54b6e6771bb9dee69fc3bfc23dee677205bddc8172f7bc076ee40d6af20deac17b5bc80b580b75c80b6e00bae4836b906bd72415b900d7724169901b6e701c77203bbb902eeee02ee5c15bddcb73bffffffbddff7cf9f7ef39e79f7cf3ef9e79ce7f7f9eff022e688135064b3d9ecd62b07044487d4ffaf }

condition:
	$a0
}

        