rule Html_Phishing_DB_3
{
strings:
	$a0 = { 646572686f6c74656e20616e6772696666656e206175662064696520706f7274616c65 }
	$a1 = { 6173206e616368666f6c67656e6465206c696e6b206265666f6c67656e20756e }

condition:
	$a0 and $a1
}

        