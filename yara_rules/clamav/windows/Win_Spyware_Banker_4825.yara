rule Win_Spyware_Banker_4825
{
strings:
	$a0 = { d332d03beabe5fbd3d00e43712b182eab535097161541c913fbaeaf3aba75f7c3f4a3b571826a82a916bf07fddf07ebcc9f650f85605b42d32e9502e6ad47a83e16ce1b0705d6cad7e84a11b275478790fda1d1c7a3abf0e4ca05795a637928b8998f7513ebb8b8bc35fe478adec46acbc456454a628661fdc6a43e72381786bfc1008485b5589eec98feca1bc890a3d693e592559 }

condition:
	$a0
}

        