rule Win_Trojan_Agent_33697
{
strings:
	$a0 = { cf284d3e3a1b46f045d68a29bba1651f5b9b813db763eeeb4b1dc7e3d565b79b16989942b81df102a4ab9229c99c9c2fe44182cd5c68ae6be02f1ed5b4ec13132149a84c3ea68e02c19f85e9d4cbcacb03cf871dc9272230f6d03e3dae9959 }

condition:
	$a0
}

        
