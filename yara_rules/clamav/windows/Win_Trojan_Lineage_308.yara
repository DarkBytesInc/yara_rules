rule Win_Trojan_Lineage_308
{
strings:
	$a0 = { ba206109a2e17ad162eedfdd23354a6c59cf60a67146b57704b1d32d07d1b1fd0fc19ab901a3facfe8fc409c4b6916330dae68d90e8b3d216125ce4566f0e2c400d52e15d0be7cddf322b2484ef76f5221b0a6ff78fdeba32a85bd75 }

condition:
	$a0
}

        
