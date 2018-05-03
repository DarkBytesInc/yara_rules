rule Win_Worm_Gaobot_6
{
strings:
	$a0 = { 9dc40fd87b2b45f70b58e50cb117b7aad9240410cca33d304d930b446fdefe1f55e0ed13c30e5fa4818f51af401e9228c8294f7f03fd6fbd2a473adb53af4eee4fe591f72f476616279da2e72ebec28f }

condition:
	$a0
}

        
