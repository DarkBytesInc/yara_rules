rule Win_Trojan_V_86
{
strings:
	$a0 = { 8cc98ed9a37403891e7203e84002b908008d1e83038a078847f843e2f88d16a803b41acd21c6068e0300c6068f03 }

condition:
	$a0
}

        
