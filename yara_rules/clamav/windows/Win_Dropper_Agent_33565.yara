rule Win_Dropper_Agent_33565
{
strings:
	$a0 = { 6680f4a4963ac546a283a59d386eebaccaebf11669d06ce117f888fc7c24a596c7b0c2095a3739fd7f2673c079552519d1cadf76099cad637794f950fa11166eb1270e1e35fa4eae0b6449ee3d462bd6be8d06c4 }

condition:
	$a0
}

        
