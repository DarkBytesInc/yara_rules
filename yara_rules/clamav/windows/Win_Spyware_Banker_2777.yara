rule Win_Spyware_Banker_2777
{
strings:
	$a0 = { 854f26f100d68ea1c2a261edd54ae9e87c977cd1a38da865c1633b479ba5db0de64e02b982082ccc7ef7cbdaa015ada7bec242ca03e9306c2fba9efc539ca11d409327abe4bdca8d6cebbaa980e29a76c0496f386e0b0f4c2bcc970a16dc2dbea0b8bb75 }

condition:
	$a0
}

        
