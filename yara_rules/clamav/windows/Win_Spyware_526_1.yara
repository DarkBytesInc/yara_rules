rule Win_Spyware_526_1
{
strings:
	$a0 = { 4d66624788e81b850b56f148e2afcb20a667f495c1dc88884caea1e79f458d09ef04be9ff4519104f1fd54a00d73755ed90471af9970f70b5a80f78b87c9b3f8c5e94f7b9ee835e03b2cc3 }

condition:
	$a0
}

        
