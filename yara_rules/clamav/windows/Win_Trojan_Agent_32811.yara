rule Win_Trojan_Agent_32811
{
strings:
	$a0 = { e9f90eed353a3c8408729b51c1e350fc23ffe8181829d39fa4c627cf2cbda9262c4e856b92534c435a5e4ca85461980f32a878a1f73d07c170bc9a14f2d24a1396 }

condition:
	$a0
}

        
