rule Win_Trojan_Darkwar_1
{
strings:
	$a0 = { 8945f489d1518b0d682d000889c8be00eb410099f7fe8945f48955f08b45f45068b01400088b55f88955f48b75f456e840fbffff83c418a1682d00088945f48b55f45268e01400088b75f88975f48b45f450e81dfbffff83c40c8b55f88955f48b75f456e89bfbffff83c404a17c2d00088945f48b55f452e817fcffff83c4046a00e8cdfbffff }
	$a1 = { 6c6f6f64656420666f72203a202564206461797320256420 }

condition:
	$a0 and $a1
}

        