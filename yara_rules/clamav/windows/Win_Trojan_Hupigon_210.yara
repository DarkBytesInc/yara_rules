rule Win_Trojan_Hupigon_210
{
strings:
	$a0 = { 07ec6e7707d449e222ba483606df76ac9b4eeb77ec166bc0a46a26e44eb1f5fe8c26adfcef2ba6f2987e4d3c988cc4e2a31d3d92bc10f2a002ff857f3c47634f9b095137a9b90593a014e54a28ab879980efabf9cff57464d7aea100e9aa33998850bfebdd3968a0dc }

condition:
	$a0
}

        
