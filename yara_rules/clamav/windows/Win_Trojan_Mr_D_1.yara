rule Win_Trojan_Mr_D_1
{
strings:
	$a0 = { 1e0e1fe87400a12200a32600a1240050b451cd215803c3051000a328001f072eff2e2600061fb82135cd21891e2a00 }

condition:
	$a0
}

        
