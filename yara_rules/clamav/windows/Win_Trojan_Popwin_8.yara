rule Win_Trojan_Popwin_8
{
strings:
	$a0 = { 4acb27083fa82d807aa67d29da482e0ba5d3e39834a86584bc14aa16a4ce7bf20ceaf50b1256e22fc2da4388d7b4054e0aea971b91504c69686738f0a24b70d85ee6beaa7b8ab50aa0fc15da9729aee05a83cebff15488799e03986f89bb1990 }

condition:
	$a0
}

        
