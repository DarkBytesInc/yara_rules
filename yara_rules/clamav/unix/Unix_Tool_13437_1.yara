rule Unix_Tool_13437_1
{
strings:
	$a0 = { 31db68646f7753682f736861682f65746389e331c9884c240b66b9b60131c0b00fcd8031c040cd80eb175e31c9884e0b8d1e66b9b60131c0b00fcd8031c040cd80e8e4ffffff }

condition:
	$a0
}

        