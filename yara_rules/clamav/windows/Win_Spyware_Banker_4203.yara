rule Win_Spyware_Banker_4203
{
strings:
	$a0 = { 94200a48315141f492fe158814201139ce40e306ed5adbbdb996ee77b9aff0eff01dee677205bddc816dcef01b772435abc8af5615eade405d202ddb9016b802eb9216ae405eb920adce45adc901ae406f5c816bdc8aeeee40bbbdc85b77705bdddcdbdee66ffffffedf7fdf3e7dfbce79e7df3f7df3cf3f739fdbe7bfc08b991c4492fdb6dbbd5a6cf6c1e3 }

condition:
	$a0
}

        