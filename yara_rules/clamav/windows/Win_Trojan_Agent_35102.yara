rule Win_Trojan_Agent_35102
{
strings:
	$a0 = { c3f9d6f9dff9faf80d3c4c16b974764378627a7a7c837e977ea54eb90fdef9c3083d169339a35bb36ac37ad28249329f74bcc9fc8a393eaa3aba3bc53ccb3dd33ed82e187897204b7a28a57c30d27e38e980407482 }

condition:
	$a0
}

        
