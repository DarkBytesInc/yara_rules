rule Win_Trojan_SdBot_1803
{
strings:
	$a0 = { 8b4f083c807eec6e4f6121864f4d34364eff5b25978d186996902efd4acce90d0be04c735361b7f7b9ca270adf3d196e5679459715f143f231b59b527b71a50ab8e616645b9d241974414e764ce758275e36634826f4436454d430cd0aab0681d96447c0db88a1bea61fd56fc961d22a }

condition:
	$a0
}

        