rule Win_Proxy_Lager_63
{
strings:
	$a0 = { d6c9fc9d16fe571cd8f70d9053d40940736367a4beff1debefdf6947f3d90b488571f34bef31a1d96ce9ec5b0bdc249b55d10a3053d474596fdb6c2eac064825d7a6b15ab4f6 }

condition:
	$a0
}

        
