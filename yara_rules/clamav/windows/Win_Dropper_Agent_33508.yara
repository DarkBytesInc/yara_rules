rule Win_Dropper_Agent_33508
{
strings:
	$a0 = { 3edcd574fa8df8cf237274aaab656062541494367ce374d9362a692832954b127325775318390a432b5caa2869bca93cdc78f526488059adcea382576773be0fcd8aa630d66a54e1be0bfbbed7cdb97b406501d4c2f63bebfb24561f48088dcc5c1fb68612876622ffcf097af4966640797f3a4501355dcd }

condition:
	$a0
}

        