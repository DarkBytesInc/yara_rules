rule Win_Spyware_Banker_2801
{
strings:
	$a0 = { bd08bc55b98be7b9765f4ce27821222556c9c83f5e92d3db5e4b718ba3fefb5fde2889f013cceddc298638639812b0d80d28b958019bb270c8345649e9d1710fc7c1831249acee825642655f7af4b0a9e4f80dcacf6393bbbeed960b53e2fb052ec5acbf }

condition:
	$a0
}

        
