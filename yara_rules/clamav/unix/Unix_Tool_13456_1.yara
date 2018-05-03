rule Unix_Tool_13456_1
{
strings:
	$a0 = { 31c0eb225b8b5308311331530431d2895c24088954240cb00b8d4c2408cd8031db89d840cd80e8d9ffffff }

condition:
	$a0
}

        
