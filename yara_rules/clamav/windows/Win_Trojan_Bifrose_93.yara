rule Win_Trojan_Bifrose_93
{
strings:
	$a0 = { b66e5500e06961d589466889567c779930b48684f3288b4f9690f03c6bf1869ca468d0359f000c1b4800c62009c706a8264500b218b54004366b8bcb882677decd68080b34b37c897e6cf3b0c5717074788e0bb1206089be80eca8ee4d90888165b1f0c7868cff5876f4779c9476febeac98a4f219aa5aa08b4ccc808773a88bc65f5e5d5b02285ad10d83c4 }

condition:
	$a0
}

        