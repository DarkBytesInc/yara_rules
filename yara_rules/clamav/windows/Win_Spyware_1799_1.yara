rule Win_Spyware_1799_1
{
strings:
	$a0 = { 535655bd4030001055ff742440ffd76a006a00ff74244ce8??f9ffff83c440803d9040001000 }
	$a1 = { 727468676f6572000000436c69656e }

condition:
	$a0 and $a1
}

        
