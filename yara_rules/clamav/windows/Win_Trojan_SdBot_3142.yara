rule Win_Trojan_SdBot_3142
{
strings:
	$a0 = { 9332b4049aef0000000079f5fd81d714fac149f53728c2486a428e92eff754c041ca0cd8d88e80d0d27900000000e77c8e9ed2214fa1b5f9866b15afd39c0c022bcedd251370d9576245cff8c52c000000001ce6fd1f1f1f7f65c8b705a39fe427aed6459c1edfb0fef892784d4a349d6f0200000000d26f0d2e85ee451add14cc7aacf17351c5345439c1fdb81fd549b055703958c6 }

condition:
	$a0
}

        