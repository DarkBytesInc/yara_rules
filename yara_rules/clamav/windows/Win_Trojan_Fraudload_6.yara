rule Win_Trojan_Fraudload_6
{
strings:
	$a0 = { 568d64240090578d642400908934248d642400906a30e98d0000006641e9c6000000578d64240090578d642400908bfc8d6424009064a58d64240090588d642400905f8d642400905e8d64240090894424fc8d6424009083ec048d6424009033c08d6424009068667db63d8d6424009068267b0d9a8d6424009068000000008d }

condition:
	$a0
}

        