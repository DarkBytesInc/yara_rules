rule Win_Dropper_Decept_3
{
strings:
	$a0 = { 2fdc7ee3e3f97a7c3ecfb3f93f17f8f17674f07f5edf1ff1f97eee4bf769a3e9e9e5f818cb7ee1dfcd6aec9d0b921c971fffd900000554456469740874787446696c6531044c656674021803546f7002 }

condition:
	$a0
}

        
