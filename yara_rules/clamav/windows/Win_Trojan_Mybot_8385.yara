rule Win_Trojan_Mybot_8385
{
strings:
	$a0 = { bd20651b02c1a0d89f0a349b64863f3c5995c3c29fe2ab674e5010fa984085ba3af0edc550111b7effeb6ea2fef61dfd513bbed4c05929e1c6941d185538a4e2cd6e99dbf8aabf86369b7afff85e6f939fe88aa28c }

condition:
	$a0
}

        
