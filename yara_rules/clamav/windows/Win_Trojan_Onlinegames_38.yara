rule Win_Trojan_Onlinegames_38
{
strings:
	$a0 = { b882954000ffe068bc8d4000750633c07402e959fcb88d344000b9d319000005206100005074067504e8160858c1e902c3e8bea87b40008bfeadbabb9540003533a14b0075057403e94c09abe2ebc3ff2500a04000ff2504a04000ff2508a04000ff250c }

condition:
	$a0
}

        