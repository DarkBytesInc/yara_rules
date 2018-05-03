rule Unix_Tool_13315_1
{
strings:
	$a0 = { eb115e31c9b130806c0eff2380e90175f6eb05e8eaffffff7489dcd9248b8487929a8b8652968b8b52528897ac068d327bf0a363f0a3 }

condition:
	$a0
}

        
