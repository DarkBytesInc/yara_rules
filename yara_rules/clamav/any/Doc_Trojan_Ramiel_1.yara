rule Doc_Trojan_Ramiel_1
{
strings:
	$a0 = { 53656c656374696f6e2e547970655465787420652822656565082420b3b9b71c2e6589242a2e652e20652c3020a9206520b3652e30651e2420b12a7165b92aa92a6520b365b11c65b92420b7b71c65202eb91cb71c65a72420b3732229 }

condition:
	$a0
}

        