rule Win_Trojan_SdBot_3668
{
strings:
	$a0 = { 0ce16a3e7a14df4ee61eeffdbcceb810b49966885a6610a58070af27e284863de063c27999726272f343116dfe06193505ae4f6d2cfd1fba461ad0c14bc5d0f63a61016224ac65b082e6c848aed7 }

condition:
	$a0
}

        
