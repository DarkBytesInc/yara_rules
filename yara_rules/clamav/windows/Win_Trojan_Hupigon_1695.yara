rule Win_Trojan_Hupigon_1695
{
strings:
	$a0 = { c692b73861820ee236cde9b0c09f0f51f94a22bef997d7a18a349d1f7c5d9bac2e81f19f268bb4adca56f4dd81a42e87463f4aaae5cdaf11b3f35fb88bdee382220d930077dd3420d0a0a9e0e212ec8f728299de96 }

condition:
	$a0
}

        
