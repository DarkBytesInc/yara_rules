rule Win_Trojan_Fakecodec_3
{
strings:
	$a0 = { 21951cfeffff038d90feffff238dacfeffff31d14181c1df00000029c9314dd8ff85f0feffff81e90001000001d181c1000700002b4db42b8df8feffff21ca42019560ffffff119550ffffff1155d4ff8d38feffff138d50feffff0b8d10ffffff49bab3 }

condition:
	$a0
}

        
