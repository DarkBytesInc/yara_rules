rule Win_Trojan_Agent_32730
{
strings:
	$a0 = { 459d3cb38491eb0be2b72ac32a050b3f47416d1404c9653ffaf64850c1b5500cfe6bfacf19642f69988efd19fee285d35f9f9968adfe541b3bf258c2a97e996e5c91b5dd4d7bf3ae86f842308bef828ebe56b9bbfcf6cb13a3bda57d1363 }

condition:
	$a0
}

        
