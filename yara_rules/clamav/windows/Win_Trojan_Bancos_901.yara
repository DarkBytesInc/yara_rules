rule Win_Trojan_Bancos_901
{
strings:
	$a0 = { de4b4f7a80ccb3c847a949fb84ca56af96c54ca6abf9a289d102947f255a769f77d749f669ecd81feb597bd9702bac07152e44080389d3b338c94b910785a76253ef7f415d5ccff6f98dc0f125da6e4fae615a07a536f1cf }

condition:
	$a0
}

        
