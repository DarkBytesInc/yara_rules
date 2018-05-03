rule Win_Worm_Agent_35383
{
strings:
	$a0 = { 627965206e6f772e2e2e }
	$a1 = { 76362e6174746163686d656e74732e61646422272c74617267657466696c65 }

condition:
	$a0 and $a1
}

        
