rule Win_Proxy_Horst_159
{
strings:
	$a0 = { 3c50ba4058ba402f1f50f2ec904098ba40e89040254ff22550ba4054ba40136f255f58ba40499d08ca1d3064e99d6141cd5ec25f168825374f185f58ba4050ba401fc947f258ba4050ba4058ba4028f76c215fe91d5c86900f235f9cba400dd4a9682a77b8765ff2840072c0b140c0b14037525724f4edac85e579b65fb804eb330ca8a8267f00ea9db0047268ffffff00f5de21 }

condition:
	$a0
}

        