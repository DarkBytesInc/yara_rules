rule Win_Dropper_Small_303
{
strings:
	$a0 = { 433a5c074d1d141a308f71a77068213f653d8264266169648a0704360d61552e96063884834803094f4d535045d706222160200b2e626174a0202f63fdc040659003776fa3dd880d0a3aa9c172cf4410123ee4256a311619156c081f6966f7ba5d40bc1bc80a77d03e2bd1202030c3984d5a90830333a90409ff }

condition:
	$a0
}

        