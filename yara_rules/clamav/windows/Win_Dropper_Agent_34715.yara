rule Win_Dropper_Agent_34715
{
strings:
	$a0 = { 558bec81c4f0feffff535657b834212000e836f6ffffbe7030200033c05568f722200064ff3064892039c039db680823 }

condition:
	$a0
}

        
