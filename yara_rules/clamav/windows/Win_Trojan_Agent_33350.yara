rule Win_Trojan_Agent_33350
{
strings:
	$a0 = { 436f6d706163743200f345c94d9aca7043544eca1337a59794878428931db818fdbd5ac51df2efea7ad385603e23b2b5decd0df70d56d8ea50d13a296aa34f5ab0a2f7b863b3d29ada31c887cc23 }

condition:
	$a0
}

        
