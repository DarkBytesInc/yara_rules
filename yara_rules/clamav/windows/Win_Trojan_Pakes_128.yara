rule Win_Trojan_Pakes_128
{
strings:
	$a0 = { eda049e46e8153007fe26214ce55cb5400a8ddb7163c900858006a4740e6f1b4b1e90edf659f03a33385f28720d34388c10081f363609327de5b00e94f58c7f65fac9100a01298b80b699d51002975ce1b28c0ebe7712600bf120e2ac6b24f9800e0aafee3835f31c0035699f88b3bf9c7a0b28682e9079be580ba2af0540349df708ef4eb5cbbd700d8f195 }

condition:
	$a0
}

        