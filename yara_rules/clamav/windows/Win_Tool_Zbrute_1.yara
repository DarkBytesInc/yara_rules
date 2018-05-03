rule Win_Tool_Zbrute_1
{
strings:
	$a0 = { 7c5f7c5f5c207c5f5f5f5c2020207c5f7c2020207c5f5f5f7c0d0a0d0a090909095772697474656e206279205a61646f786c }

condition:
	$a0
}

        
