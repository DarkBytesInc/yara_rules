rule Win_Trojan_Surila_2
{
strings:
	$a0 = { 3753e695420f055c7f11742c91cb4ec0fcd84a30518c2fdba740c39922efd4ed6b1e3e845b7775f201af637b5daca754c191ab8b48be0ac0ef565eb5ea1ecbbc64d9adfa6b26c433c4c3bdbc91c803eb3ebb36ea0487b271710966501bd7f95ed5e66e42c1d57f8c209fe3fc2839f76a }

condition:
	$a0
}

        
