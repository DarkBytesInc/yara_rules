rule Win_Trojan_LdPinch_24
{
strings:
	$a0 = { 75657374696f6e7328257329143c65771c26623d1626633dffffdb770f703a2f2f77002e706d726b2e64652f50726f64756b746d6fffe6ff616e6167656d656e742f5f6675725f4175746f456e2f67fef66d6b077e6e306870005f0f745f6f6b5f316bbf2fc84974616b463f26211f6ffff76d3d932669703106736f }

condition:
	$a0
}

        