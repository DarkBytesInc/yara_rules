rule Win_Trojan_Small_86
{
strings:
	$a0 = { ac0cb0767b5b2866ddd443a4890275a8891e812d5bf98b45ac890bb00cb2be16d9cc704870600751301bacdbb4205e007cac91deeb9ecd63a9e46c1c020b14ef64739b32840bc5bdd4cc33dbb0cfba8c22030b305c502b6c6cd9c920236c6c78 }

condition:
	$a0
}

        
