rule Win_Trojan_Mybot_5755
{
strings:
	$a0 = { 464f54548b3d23af99f8e61d91710b8d56f68d2ed1937a2ef7ab59e4fec557b90b5fa44e78712bef1d574f2eb3edd04bc95245dbfa8f3506ebd1baae234fd6cbde6863d9051f3473e256c2bb2634e80bd19edb4d5aa05bbb092bcd1af36fde163eb8f3add229872cfa64c73cf3d3ceb47eec9e }

condition:
	$a0
}

        
