rule Win_Trojan_LdPinch_121
{
strings:
	$a0 = { 3daa6fb55b5c56253c615bfc2e0da355cce3d5df987c07857ea2e7fea0afb440109ae1849eda79451350c7b7a4fefa19d524d491ae4b8df385fbaa5bebbb04c3fe512fb6623ae14f73aafda983f08ca8ba2bba2c4e3f376a7c146df666d7518203134807e499b9caf7d0f9508c7f2d7f05dd4a9b3f4070fb39ef29405e6b6b67 }

condition:
	$a0
}

        
