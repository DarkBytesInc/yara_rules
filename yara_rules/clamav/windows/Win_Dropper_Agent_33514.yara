rule Win_Dropper_Agent_33514
{
strings:
	$a0 = { 8f135b625e87be946128c58e84cb01cdcc28fac155439dd633d594983c47f703bde683fb2c25446bb14277f9ef463ed7669e175de343430dc9f5a3fd54733b56b58d50df2f1de8d0db83feb4f2337559bf513efa }

condition:
	$a0
}

        
