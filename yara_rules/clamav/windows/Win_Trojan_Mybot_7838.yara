rule Win_Trojan_Mybot_7838
{
strings:
	$a0 = { 8c183060c6f2214c26fde84d98a9b31298df136e4444cc136d8b186631889baa54442a110a2926fc126d92c454dd3162bf912cab2677af01eb975e0befd6b8bae4eb935ae3eb5c7d6b8fbe4eb975e1cd7853be4d79ffcf3af7efc1ff7f7df9ebefef96ed469c000c853cc603fed0a577fff7586eca8518e2dfcf8b8d83 }

condition:
	$a0
}

        
