rule Win_Dropper_Small_1904
{
strings:
	$a0 = { 8e48e8978dedde444335fd04473c065461442a52396a393a373b613363096de374070ce8aafeff118b3538433ad800ae8d43085055ffd690d3452c9e12d772c28490815309929b1a55880136a8ad184454320a1941a1331611646c262202c8940b1ec624c3231a1578302b0c4821153d432b0d45a35e9158 }

condition:
	$a0
}

        